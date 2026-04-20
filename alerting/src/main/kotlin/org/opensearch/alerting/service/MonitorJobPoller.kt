/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.service

import org.apache.logging.log4j.LogManager
import org.opensearch.alerting.action.ExecuteMonitorAction
import org.opensearch.alerting.action.ExecuteMonitorRequest
import org.opensearch.common.lifecycle.AbstractLifecycleComponent
import org.opensearch.common.unit.TimeValue
import org.opensearch.common.xcontent.LoggingDeprecationHandler
import org.opensearch.common.xcontent.XContentType
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.core.xcontent.NamedXContentRegistry
import org.opensearch.core.xcontent.XContentParserUtils
import org.opensearch.transport.client.Client
import software.amazon.awssdk.services.sqs.SqsClient
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest
import software.amazon.awssdk.services.sqs.model.Message
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest
import java.time.Instant
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Polls SQS queues for monitor execution messages and dispatches them
 * to TransportExecuteMonitorAction. Runs a fixed thread pool of workers
 * that round-robin across queue URLs provided by [JobQueueUrlsProvider].
 */
class MonitorJobPoller(
    private val jobQueueUrlsProvider: JobQueueUrlsProvider,
    private val sqsClient: SqsClient,
    private val xContentRegistry: NamedXContentRegistry,
    private val client: Client
) : AbstractLifecycleComponent() {

    private val logger = LogManager.getLogger(javaClass)
    private lateinit var executor: ExecutorService

    override fun doStart() {
        logger.info("Starting MonitorJobPoller with $POLLER_THREAD_COUNT threads")
        executor = Executors.newFixedThreadPool(POLLER_THREAD_COUNT)
        repeat(POLLER_THREAD_COUNT) { executor.submit(PollWorker()) }
    }

    override fun doStop() {
        logger.info("Stopping MonitorJobPoller")
        executor.shutdownNow()
        executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)
        sqsClient.close()
    }

    override fun doClose() {}

    private inner class PollWorker : Runnable {
        private val queueIndex = AtomicInteger(0)

        override fun run() {
            while (!Thread.currentThread().isInterrupted) {
                try {
                    val queueUrls = jobQueueUrlsProvider.getQueueUrls()
                    if (queueUrls.isEmpty()) {
                        // TODO: add sleep to avoid busy-loop
                        continue
                    }
                    val queueUrl = queueUrls[queueIndex.getAndIncrement() % queueUrls.size]

                    val messages = receiveMessages(queueUrl)
                    if (messages.isEmpty()) {
                        // TODO: add sleep to avoid busy-loop
                        continue
                    }

                    val message = messages[0]
                    try {
                        val (monitor, jobStartTime) = parseMessage(message.body())
                        executeMonitor(monitor, jobStartTime)
                        deleteMessage(queueUrl, message)
                    } catch (e: Exception) {
                        logger.error("Failed to process SQS message {}", message.messageId(), e)
                        // Don't delete — visibility timeout expires, SQS redelivers
                    }
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                } catch (e: Exception) {
                    logger.error("Error in MonitorJobPoller worker", e)
                }
            }
            logger.info("MonitorJobPoller worker exiting")
        }
    }

    private fun executeMonitor(monitor: Monitor, jobStartTime: Instant) {
        val request = ExecuteMonitorRequest(
            dryrun = false,
            requestEnd = TimeValue(jobStartTime.toEpochMilli()),
            monitorId = null,
            monitor = monitor,
            requestStart = null
        )
        client.execute(ExecuteMonitorAction.INSTANCE, request).actionGet()
    }

    internal fun receiveMessages(queueUrl: String): List<Message> {
        val request = ReceiveMessageRequest.builder()
            .queueUrl(queueUrl)
            .maxNumberOfMessages(1)
            .waitTimeSeconds(0)
            .visibilityTimeout(VISIBILITY_TIMEOUT_SECONDS)
            .build()
        return sqsClient.receiveMessage(request).messages()
    }

    internal fun deleteMessage(queueUrl: String, message: Message) {
        val request = DeleteMessageRequest.builder()
            .queueUrl(queueUrl)
            .receiptHandle(message.receiptHandle())
            .build()
        sqsClient.deleteMessage(request)
    }

    internal fun parseMessage(body: String): Pair<Monitor, Instant> {
        var jobStartTime: Instant = Instant.now()
        var monitorConfigJson: String? = null

        XContentType.JSON.xContent().createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE, body).use { parser ->
            XContentParserUtils.ensureExpectedToken(parser.nextToken(), parser.currentToken(), parser)
            while (parser.nextToken() != null) {
                val fieldName = parser.currentName()
                parser.nextToken()
                when (fieldName) {
                    "job_start_time" -> jobStartTime = Instant.parse(parser.text())
                    "monitorConfig" -> monitorConfigJson = parser.text()
                    else -> parser.skipChildren()
                }
            }
        }

        requireNotNull(monitorConfigJson) { "SQS message missing monitorConfig field" }

        val monitor = XContentType.JSON.xContent()
            .createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE, monitorConfigJson).use { parser ->
                parser.nextToken()
                Monitor.parse(parser)
            }

        return Pair(monitor, jobStartTime)
    }

    companion object {
        const val POLLER_THREAD_COUNT = 10
        const val VISIBILITY_TIMEOUT_SECONDS = 90
    }
}
