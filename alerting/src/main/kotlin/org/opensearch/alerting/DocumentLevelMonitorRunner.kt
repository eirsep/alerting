/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting

import org.apache.logging.log4j.LogManager
import org.opensearch.ExceptionsHelper
import org.opensearch.OpenSearchStatusException
import org.opensearch.action.ActionListenerResponseHandler
import org.opensearch.action.DocWriteRequest
import org.opensearch.action.bulk.BulkRequest
import org.opensearch.action.bulk.BulkResponse
import org.opensearch.action.index.IndexRequest
import org.opensearch.action.search.SearchAction
import org.opensearch.action.search.SearchRequest
import org.opensearch.action.search.SearchResponse
import org.opensearch.action.support.GroupedActionListener
import org.opensearch.action.support.WriteRequest
import org.opensearch.alerting.action.DocLevelMonitorFanOutAction
import org.opensearch.alerting.action.DocLevelMonitorFanOutRequest
import org.opensearch.alerting.action.DocLevelMonitorFanOutResponse
import org.opensearch.alerting.model.DocumentLevelTriggerRunResult
import org.opensearch.alerting.model.IndexExecutionContext
import org.opensearch.alerting.model.InputRunResults
import org.opensearch.alerting.model.MonitorMetadata
import org.opensearch.alerting.model.MonitorRunResult
import org.opensearch.alerting.model.userErrorMessage
import org.opensearch.alerting.opensearchapi.suspendUntil
import org.opensearch.alerting.script.DocumentLevelTriggerExecutionContext
import org.opensearch.alerting.settings.AlertingSettings.Companion.DOC_LEVEL_MONITOR_FETCH_ONLY_QUERY_FIELDS_ENABLED
import org.opensearch.alerting.util.AlertingException
import org.opensearch.alerting.util.IndexUtils
import org.opensearch.alerting.util.defaultToPerExecutionAction
import org.opensearch.alerting.util.getActionExecutionPolicy
import org.opensearch.alerting.workflow.WorkflowRunContext
import org.opensearch.client.Client
import org.opensearch.client.node.NodeClient
import org.opensearch.cluster.metadata.IndexMetadata
import org.opensearch.cluster.node.DiscoveryNode
import org.opensearch.cluster.routing.ShardRouting
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.xcontent.XContentFactory
import org.opensearch.common.xcontent.XContentType
import org.opensearch.commons.alerting.AlertingPluginInterface
import org.opensearch.commons.alerting.action.PublishFindingsRequest
import org.opensearch.commons.alerting.action.SubscribeFindingsResponse
import org.opensearch.commons.alerting.model.ActionExecutionResult
import org.opensearch.commons.alerting.model.Alert
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.commons.alerting.model.DocumentLevelTrigger
import org.opensearch.commons.alerting.model.Finding
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.model.action.PerAlertActionScope
import org.opensearch.commons.alerting.util.string
import org.opensearch.core.action.ActionListener
import org.opensearch.core.common.bytes.BytesReference
import org.opensearch.core.common.io.stream.Writeable
import org.opensearch.core.index.shard.ShardId
import org.opensearch.core.rest.RestStatus
import org.opensearch.core.xcontent.ToXContent
import org.opensearch.core.xcontent.XContentBuilder
import org.opensearch.index.IndexNotFoundException
import org.opensearch.index.query.BoolQueryBuilder
import org.opensearch.index.query.Operator
import org.opensearch.index.query.QueryBuilders
import org.opensearch.index.seqno.SequenceNumbers
import org.opensearch.indices.IndexClosedException
import org.opensearch.percolator.PercolateQueryBuilderExt
import org.opensearch.search.SearchHit
import org.opensearch.search.SearchHits
import org.opensearch.search.builder.SearchSourceBuilder
import org.opensearch.search.sort.SortOrder
import org.opensearch.transport.TransportException
import org.opensearch.transport.TransportRequestOptions
import org.opensearch.transport.TransportService
import java.io.IOException
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import java.util.stream.Collectors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlin.math.max

object DocumentLevelMonitorRunner : MonitorRunner() {
    private val logger = LogManager.getLogger(javaClass)

    override suspend fun runMonitor(
        monitor: Monitor,
        monitorCtx: MonitorRunnerExecutionContext,
        periodStart: Instant,
        periodEnd: Instant,
        dryrun: Boolean,
        workflowRunContext: WorkflowRunContext?,
        executionId: String,
        transportService: TransportService?,
    ): MonitorRunResult<DocumentLevelTriggerRunResult> {
        if (transportService == null)
            throw RuntimeException("transport service should not be null")
        logger.debug("Document-level-monitor is running ...")
        val isTempMonitor = dryrun || monitor.id == Monitor.NO_ID
        var monitorResult = MonitorRunResult<DocumentLevelTriggerRunResult>(monitor.name, periodStart, periodEnd)
        var nonPercolateSearchesTimeTaken = AtomicLong(0)
        var percolateQueriesTimeTaken = AtomicLong(0)
        var totalDocsQueried = AtomicLong(0)
        var docTransformTimeTaken = AtomicLong(0)
        try {
            monitorCtx.alertIndices!!.createOrUpdateAlertIndex(monitor.dataSources)
            monitorCtx.alertIndices!!.createOrUpdateInitialAlertHistoryIndex(monitor.dataSources)
            monitorCtx.alertIndices!!.createOrUpdateInitialFindingHistoryIndex(monitor.dataSources)
        } catch (e: Exception) {
            val id = if (monitor.id.trim().isEmpty()) "_na_" else monitor.id
            logger.error("Error setting up alerts and findings indices for monitor: $id", e)
            monitorResult = monitorResult.copy(error = AlertingException.wrap(e))
        }

        try {
            validate(monitor)
        } catch (e: Exception) {
            logger.error("Failed to start Document-level-monitor. Error: ${e.message}")
            monitorResult = monitorResult.copy(error = AlertingException.wrap(e))
        }

        var (monitorMetadata, _) = MonitorMetadataService.getOrCreateMetadata(
            monitor = monitor,
            createWithRunContext = false,
            skipIndex = isTempMonitor,
            workflowRunContext?.workflowMetadataId
        )

        val docLevelMonitorInput = monitor.inputs[0] as DocLevelMonitorInput

        val queries: List<DocLevelQuery> = docLevelMonitorInput.queries

        val lastRunContext = if (monitorMetadata.lastRunContext.isNullOrEmpty()) mutableMapOf()
        else monitorMetadata.lastRunContext.toMutableMap() as MutableMap<String, MutableMap<String, Any>>

        val updatedLastRunContext = lastRunContext.toMutableMap()

        try {
            // Resolve all passed indices to concrete indices
            val clusterService = monitorCtx.clusterService!!
            val allConcreteIndices = IndexUtils.resolveAllIndices(
                docLevelMonitorInput.indices,
                clusterService,
                monitorCtx.indexNameExpressionResolver!!
            )
            if (allConcreteIndices.isEmpty()) {
                logger.error("indices not found-${docLevelMonitorInput.indices.joinToString(",")}")
                throw IndexNotFoundException(docLevelMonitorInput.indices.joinToString(","))
            }

            val docLevelMonitorQueries = monitorCtx.docLevelMonitorQueries!!
            docLevelMonitorQueries.initDocLevelQueryIndex(monitor.dataSources)
            docLevelMonitorQueries.indexDocLevelQueries(
                monitor = monitor,
                monitorId = monitor.id,
                monitorMetadata,
                indexTimeout = monitorCtx.indexTimeout!!
            )

            // cleanup old indices that are not monitored anymore from the same monitor
            val runContextKeys = updatedLastRunContext.keys.toMutableSet()
            for (ind in runContextKeys) {
                if (!allConcreteIndices.contains(ind)) {
                    updatedLastRunContext.remove(ind)
                }
            }

            // Map of document ids per index when monitor is workflow delegate and has chained findings
            val matchingDocIdsPerIndex = workflowRunContext?.matchingDocIdsPerIndex

            /* Contains list of docs source that are held in memory to submit to percolate query against query index.
            * Docs are fetched from the source index per shard and transformed.*/
            val transformedDocs = mutableListOf<Pair<String, TransformedDocDto>>()
            val docsSizeInBytes = AtomicLong(0)
            val concreteIndicesSeenSoFar = mutableListOf<String>()
            val updatedIndexNames = mutableListOf<String>()
            val queryingStartTimeMillis = System.currentTimeMillis()
            val docLevelMonitorFanOutResponses: MutableList<DocLevelMonitorFanOutResponse> = mutableListOf()
            docLevelMonitorInput.indices.forEach { indexName ->

                var concreteIndices = IndexUtils.resolveAllIndices(
                    listOf(indexName),
                    clusterService,
                    monitorCtx.indexNameExpressionResolver!!
                )
                var lastWriteIndex: String? = null
                if (IndexUtils.isAlias(indexName, clusterService.state()) ||
                    IndexUtils.isDataStream(indexName, clusterService.state())
                ) {
                    lastWriteIndex = concreteIndices.find { lastRunContext.containsKey(it) }
                    if (lastWriteIndex != null) {
                        val lastWriteIndexCreationDate =
                            IndexUtils.getCreationDateForIndex(lastWriteIndex, clusterService.state())
                        concreteIndices = IndexUtils.getNewestIndicesByCreationDate(
                            concreteIndices,
                            clusterService.state(),
                            lastWriteIndexCreationDate
                        )
                    }
                }
                concreteIndicesSeenSoFar.addAll(concreteIndices)
                val updatedIndexName = indexName.replace("*", "_")
                updatedIndexNames.add(updatedIndexName)
                val conflictingFields = docLevelMonitorQueries.getAllConflictingFields(
                    clusterService.state(),
                    concreteIndices
                )

                concreteIndices.forEach { concreteIndexName ->
                    // Prepare lastRunContext for each index
                    val indexLastRunContext = lastRunContext.getOrPut(concreteIndexName) {
                        val isIndexCreatedRecently = createdRecently(
                            monitor,
                            periodStart,
                            periodEnd,
                            clusterService.state().metadata.index(concreteIndexName)
                        )
                        MonitorMetadataService.createRunContextForIndex(concreteIndexName, isIndexCreatedRecently)
                    }

                    // Prepare updatedLastRunContext for each index
                    val indexUpdatedRunContext = initializeNewLastRunContext(
                        indexLastRunContext.toMutableMap(),
                        monitorCtx,
                        concreteIndexName
                    ) as MutableMap<String, Any>
                    if (IndexUtils.isAlias(indexName, clusterService.state()) ||
                        IndexUtils.isDataStream(indexName, clusterService.state())
                    ) {
                        if (concreteIndexName == IndexUtils.getWriteIndex(indexName, clusterService.state())) {
                            updatedLastRunContext.remove(lastWriteIndex)
                            updatedLastRunContext[concreteIndexName] = indexUpdatedRunContext
                        }
                    } else {
                        updatedLastRunContext[concreteIndexName] = indexUpdatedRunContext
                    }

                    val count: Int = indexLastRunContext["shards_count"] as Int
                    for (i: Int in 0 until count) {
                        val shard = i.toString()

                        // update lastRunContext if its a temp monitor as we only want to view the last bit of data then
                        // TODO: If dryrun, we should make it so we limit the search as this could still potentially give us lots of data
                        if (isTempMonitor) {
                            indexLastRunContext[shard] = max(-1, (indexUpdatedRunContext[shard] as String).toInt() - 10)
                        }
                    }
                    val fieldsToBeQueried = mutableSetOf<String>()

                    for (it in queries) {
                        if (it.queryFieldNames.isEmpty()) {
                            fieldsToBeQueried.clear()
                            logger.debug(
                                "Monitor ${monitor.id} : " +
                                    "Doc Level query ${it.id} : ${it.query} doesn't have queryFieldNames populated. " +
                                    "Cannot optimize monitor to fetch only query-relevant fields. " +
                                    "Querying entire doc source."
                            )
                            break
                        }
                        fieldsToBeQueried.addAll(it.queryFieldNames)
                    }
                    logger.error("PERF_DEBUG: Monitor ${monitor.id} Query field names: ${fieldsToBeQueried.joinToString()}}")
                    val indexExecutionContext = IndexExecutionContext(
                        queries,
                        indexLastRunContext,
                        indexUpdatedRunContext,
                        updatedIndexName,
                        concreteIndexName,
                        updatedIndexNames,
                        concreteIndices,
                        conflictingFields.toList(),
                        matchingDocIdsPerIndex?.get(concreteIndexName),
                    )
                    val shards = mutableSetOf<String>()
                    shards.addAll(indexUpdatedRunContext.keys)
                    shards.remove("index")
                    shards.remove("shards_count")

                    val nodeMap = getNodes(monitorCtx)
                    val nodeShardAssignments = distributeShards(
                        monitorCtx,
                        nodeMap.keys.toList(),
                        shards.toList(),
                        concreteIndexName
                    )
                    /*                    val dlmfor: DocLevelMonitorFanOutResponse = monitorCtx.client!!.suspendUntil {
                                            execute(DocLevelMonitorFanOutAction.INSTANCE, docLevelMonitorFanOutRequest1, it)
                                        }
                                        val lastRunContextFromResponse = dlmfor.lastRunContexts as MutableMap<String, MutableMap<String, Any>>
                    <<<<<<< HEAD
                                        updatedLastRunContext[concreteIndexName] = lastRunContextFromResponse[concreteIndexName] as MutableMap<String, Any>
                                        logger.error(dlmfor)
                    =======
                                        lastRunContext[concreteIndexName] = lastRunContextFromResponse[concreteIndexName] as MutableMap<String, Any>
                                        logger.error(dlmfor)*/

                    nodeShardAssignments.forEach {
                        logger.info(it.key)
                        it.value.forEach { it1 ->
                            logger.info(it1.id.toString())
                        }
                    }
                    val responses: Collection<DocLevelMonitorFanOutResponse> = suspendCoroutine { cont ->
                        val listener = GroupedActionListener(
                            object : ActionListener<Collection<DocLevelMonitorFanOutResponse>> {
                                override fun onResponse(response: Collection<DocLevelMonitorFanOutResponse>) {
                                    logger.info("hit here1")
                                    cont.resume(response)
                                }

                                override fun onFailure(e: Exception) {
                                    logger.info("Fan out failed", e)
                                    if (e.cause is Exception) // unwrap remote transport exception
                                        cont.resumeWithException(e.cause as Exception)
                                    else
                                        cont.resumeWithException(e)
                                }
                            },
                            nodeMap.size
                        )
                        val responseReader = Writeable.Reader {
                            DocLevelMonitorFanOutResponse(it)
                        }
                        for (node in nodeMap) {
                            val docLevelMonitorFanOutRequest = DocLevelMonitorFanOutRequest(
                                node.key,
                                monitor,
                                dryrun,
                                monitorMetadata,
                                executionId,
                                listOf(indexExecutionContext),
                                nodeShardAssignments[node.key]!!.toList(),
                                workflowRunContext
                            )

                            transportService.sendRequest(
                                node.value,
                                DocLevelMonitorFanOutAction.NAME,
                                docLevelMonitorFanOutRequest,
                                TransportRequestOptions.EMPTY,
                                object : ActionListenerResponseHandler<DocLevelMonitorFanOutResponse>(listener, responseReader) {
                                    override fun handleException(e: TransportException) {
                                        listener.onFailure(e)
                                    }

                                    override fun handleResponse(response: DocLevelMonitorFanOutResponse) {
                                        listener.onResponse(response)
                                    }
                                }
                            )
                        }
                    }
                    docLevelMonitorFanOutResponses.addAll(responses)
                }
            }
            updateLastRunContextFromFanOutResponses(docLevelMonitorFanOutResponses, updatedLastRunContext)
            val triggerResults = buildTriggerResults(docLevelMonitorFanOutResponses)
            val inputRunResults = buildInputRunResults(docLevelMonitorFanOutResponses)
            if (!isTempMonitor) {
                // If any error happened during trigger execution, upsert monitor error alert
                val errorMessage = constructErrorMessageFromTriggerResults(triggerResults)
                if (errorMessage.isNotEmpty()) {
                    monitorCtx.alertService!!.upsertMonitorErrorAlert(
                        monitor = monitor,
                        errorMessage = errorMessage,
                        executionId = executionId,
                        workflowRunContext
                    )
                } else {
                    onSuccessfulMonitorRun(monitorCtx, monitor)
                }
                MonitorMetadataService.upsertMetadata(
                    monitorMetadata.copy(lastRunContext = updatedLastRunContext),
                    true
                )
            }
            // TODO: Update the Document as part of the Trigger and return back the trigger action result
            return monitorResult.copy(triggerResults = triggerResults, inputResults = inputRunResults)
        } catch (e: Exception) {
            val errorMessage = ExceptionsHelper.detailedMessage(e)
            if (!isTempMonitor) {
                monitorCtx.alertService!!.upsertMonitorErrorAlert(monitor, errorMessage, executionId, workflowRunContext)
            }
            logger.error("Failed running Document-level-monitor ${monitor.name}", e)
            val alertingException = AlertingException(
                errorMessage,
                RestStatus.INTERNAL_SERVER_ERROR,
                e
            )
            return monitorResult.copy(
                error = alertingException,
                inputResults = InputRunResults(emptyList(), alertingException)
            )
        } finally {
            logger.error(
                "PERF_DEBUG_STATS: Monitor ${monitor.id} " +
                    "Time spent on fetching data from shards in millis: $nonPercolateSearchesTimeTaken"
            )
            logger.error("PERF_DEBUG_STATS: Monitor ${monitor.id} Time spent on percolate queries in millis: $percolateQueriesTimeTaken")
            logger.error("PERF_DEBUG_STATS: Monitor ${monitor.id} Time spent on transforming doc fields in millis: $docTransformTimeTaken")
            logger.error("PERF_DEBUG_STATS: Monitor ${monitor.id} Num docs queried: $totalDocsQueried")
        }
    }

    private fun buildInputRunResults(docLevelMonitorFanOutResponses: MutableList<DocLevelMonitorFanOutResponse>): InputRunResults {
        val inputRunResults = mutableMapOf<String, MutableSet<String>>()
        var error: Exception? = null
        for (response in docLevelMonitorFanOutResponses) {
            if (error == null && response.inputResults.error != null)
                error = response.inputResults.error

            val partialResult = response.inputResults.results
            for (result in partialResult) {
                for (id in result.keys) {
                    inputRunResults.getOrPut(id) { mutableSetOf() }.addAll(result[id] as Collection<String>)
                }
            }
        }
        return InputRunResults(listOf(inputRunResults), error)
    }

    private fun buildTriggerResults(
        docLevelMonitorFanOutResponses: MutableList<DocLevelMonitorFanOutResponse>,
    ): MutableMap<String, DocumentLevelTriggerRunResult> {
        val triggerResults = mutableMapOf<String, DocumentLevelTriggerRunResult>()
        for (res in docLevelMonitorFanOutResponses) {
            for (triggerId in res.triggerResults.keys) {
                val documentLevelTriggerRunResult = res.triggerResults[triggerId]
                if (documentLevelTriggerRunResult != null) {
                    if (false == triggerResults.contains(triggerId)) {
                        triggerResults[triggerId] = documentLevelTriggerRunResult
                    } else {
                        val currVal = triggerResults[triggerId]
                        val newTrigggeredDocs = mutableListOf<String>()
                        newTrigggeredDocs.addAll(currVal!!.triggeredDocs)
                        newTrigggeredDocs.addAll(documentLevelTriggerRunResult.triggeredDocs)
                        triggerResults.put(
                            triggerId,
                            currVal.copy(
                                triggeredDocs = newTrigggeredDocs,
                                error = if (currVal.error != null) currVal.error else documentLevelTriggerRunResult.error
                            )
                        )
                    }
                }
            }
        }
        return triggerResults
    }

    private suspend fun onSuccessfulMonitorRun(monitorCtx: MonitorRunnerExecutionContext, monitor: Monitor) {
        monitorCtx.alertService!!.clearMonitorErrorAlert(monitor)
        if (monitor.dataSources.alertsHistoryIndex != null) {
            monitorCtx.alertService!!.moveClearedErrorAlertsToHistory(
                monitor.id,
                monitor.dataSources.alertsIndex,
                monitor.dataSources.alertsHistoryIndex!!
            )
        }
    }

    private fun constructErrorMessageFromTriggerResults(
        triggerResults: MutableMap<String, DocumentLevelTriggerRunResult>? = null,
    ): String {
        var errorMessage = ""
        if (triggerResults != null) {
            val triggersErrorBuilder = StringBuilder()
            triggerResults.forEach {
                if (it.value.error != null) {
                    triggersErrorBuilder.append("[${it.key}]: [${it.value.error!!.userErrorMessage()}]").append(" | ")
                }
            }
            if (triggersErrorBuilder.isNotEmpty()) {
                errorMessage = "Trigger errors: $triggersErrorBuilder"
            }
        }
        return errorMessage
    }

    private suspend fun runForEachDocTrigger(
        monitorCtx: MonitorRunnerExecutionContext,
        monitorResult: MonitorRunResult<DocumentLevelTriggerRunResult>,
        trigger: DocumentLevelTrigger,
        monitor: Monitor,
        idQueryMap: Map<String, DocLevelQuery>,
        docsToQueries: MutableMap<String, MutableList<String>>,
        queryToDocIds: Map<DocLevelQuery, Set<String>>,
        dryrun: Boolean,
        workflowRunContext: WorkflowRunContext?,
        executionId: String,
    ): DocumentLevelTriggerRunResult {
        val triggerCtx = DocumentLevelTriggerExecutionContext(monitor, trigger)
        val triggerResult = monitorCtx.triggerService!!.runDocLevelTrigger(monitor, trigger, queryToDocIds)

        val triggerFindingDocPairs = mutableListOf<Pair<String, String>>()

        // TODO: Implement throttling for findings
        val findingToDocPairs = createFindings(
            monitor,
            monitorCtx,
            docsToQueries,
            idQueryMap,
            !dryrun && monitor.id != Monitor.NO_ID,
            executionId
        )

        findingToDocPairs.forEach {
            // Only pick those entries whose docs have triggers associated with them
            if (triggerResult.triggeredDocs.contains(it.second)) {
                triggerFindingDocPairs.add(Pair(it.first, it.second))
            }
        }

        val actionCtx = triggerCtx.copy(
            triggeredDocs = triggerResult.triggeredDocs,
            relatedFindings = findingToDocPairs.map { it.first },
            error = monitorResult.error ?: triggerResult.error
        )

        val alerts = mutableListOf<Alert>()
        triggerFindingDocPairs.forEach {
            val alert = monitorCtx.alertService!!.composeDocLevelAlert(
                listOf(it.first),
                listOf(it.second),
                triggerCtx,
                monitorResult.alertError() ?: triggerResult.alertError(),
                executionId = executionId,
                workflorwRunContext = workflowRunContext
            )
            alerts.add(alert)
        }

        val shouldDefaultToPerExecution = defaultToPerExecutionAction(
            monitorCtx.maxActionableAlertCount,
            monitorId = monitor.id,
            triggerId = trigger.id,
            totalActionableAlertCount = alerts.size,
            monitorOrTriggerError = actionCtx.error
        )

        for (action in trigger.actions) {
            val actionExecutionScope = action.getActionExecutionPolicy(monitor)!!.actionExecutionScope
            if (actionExecutionScope is PerAlertActionScope && !shouldDefaultToPerExecution) {
                for (alert in alerts) {
                    val actionResults =
                        this.runAction(action, actionCtx.copy(alerts = listOf(alert)), monitorCtx, monitor, dryrun)
                    triggerResult.actionResultsMap.getOrPut(alert.id) { mutableMapOf() }
                    triggerResult.actionResultsMap[alert.id]?.set(action.id, actionResults)
                }
            } else if (alerts.isNotEmpty()) {
                val actionResults = this.runAction(action, actionCtx.copy(alerts = alerts), monitorCtx, monitor, dryrun)
                for (alert in alerts) {
                    triggerResult.actionResultsMap.getOrPut(alert.id) { mutableMapOf() }
                    triggerResult.actionResultsMap[alert.id]?.set(action.id, actionResults)
                }
            }
        }

        // Alerts are saved after the actions since if there are failures in the actions, they can be stated in the alert
        if (!dryrun && monitor.id != Monitor.NO_ID) {
            val updatedAlerts = alerts.map { alert ->
                val actionResults = triggerResult.actionResultsMap.getOrDefault(alert.id, emptyMap())
                val actionExecutionResults = actionResults.values.map { actionRunResult ->
                    ActionExecutionResult(
                        actionRunResult.actionId,
                        actionRunResult.executionTime,
                        if (actionRunResult.throttled) 1 else 0
                    )
                }
                alert.copy(actionExecutionResults = actionExecutionResults)
            }

            monitorCtx.retryPolicy?.let {
                monitorCtx.alertService!!.saveAlerts(
                    monitor.dataSources,
                    updatedAlerts,
                    it,
                    routingId = monitor.id
                )
            }
        }
        return triggerResult
    }

    private suspend fun createFindings(
        monitor: Monitor,
        monitorCtx: MonitorRunnerExecutionContext,
        docsToQueries: MutableMap<String, MutableList<String>>,
        idQueryMap: Map<String, DocLevelQuery>,
        shouldCreateFinding: Boolean,
        workflowExecutionId: String? = null,
    ): List<Pair<String, String>> {

        val findingDocPairs = mutableListOf<Pair<String, String>>()
        val findings = mutableListOf<Finding>()
        val indexRequests = mutableListOf<IndexRequest>()

        docsToQueries.forEach {
            val triggeredQueries = it.value.map { queryId -> idQueryMap[queryId]!! }

            // Before the "|" is the doc id and after the "|" is the index
            val docIndex = it.key.split("|")

            val finding = Finding(
                id = UUID.randomUUID().toString(),
                relatedDocIds = listOf(docIndex[0]),
                correlatedDocIds = listOf(docIndex[0]),
                monitorId = monitor.id,
                monitorName = monitor.name,
                index = docIndex[1],
                docLevelQueries = triggeredQueries,
                timestamp = Instant.now(),
                executionId = workflowExecutionId
            )
            findingDocPairs.add(Pair(finding.id, it.key))
            findings.add(finding)

            val findingStr =
                finding.toXContent(XContentBuilder.builder(XContentType.JSON.xContent()), ToXContent.EMPTY_PARAMS)
                    .string()
            logger.debug("Findings: $findingStr")

            if (shouldCreateFinding) {
                indexRequests += IndexRequest(monitor.dataSources.findingsIndex)
                    .source(findingStr, XContentType.JSON)
                    .id(finding.id)
                    .routing(finding.id)
                    .opType(DocWriteRequest.OpType.CREATE)
            }
        }

        if (indexRequests.isNotEmpty()) {
            val bulkResponse: BulkResponse = monitorCtx.client!!.suspendUntil {
                bulk(BulkRequest().add(indexRequests).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE), it)
            }
            if (bulkResponse.hasFailures()) {
                bulkResponse.items.forEach { item ->
                    if (item.isFailed) {
                        logger.debug("Failed indexing the finding ${item.id} of monitor [${monitor.id}]")
                    }
                }
            } else {
                logger.debug("[${bulkResponse.items.size}] All findings successfully indexed.")
            }
        }
        return findingDocPairs
    }

    private fun publishFinding(
        monitor: Monitor,
        monitorCtx: MonitorRunnerExecutionContext,
        finding: Finding,
    ) {
        val publishFindingsRequest = PublishFindingsRequest(monitor.id, finding)
        AlertingPluginInterface.publishFinding(
            monitorCtx.client!! as NodeClient,
            publishFindingsRequest,
            object : ActionListener<SubscribeFindingsResponse> {
                override fun onResponse(response: SubscribeFindingsResponse) {}

                override fun onFailure(e: Exception) {}
            }
        )
    }

    private fun updateLastRunContextFromFanOutResponses(
        docLevelMonitorFanOutResponses: MutableList<DocLevelMonitorFanOutResponse>,
        updatedLastRunContext: MutableMap<String, MutableMap<String, Any>>,
    ) {
        // Prepare updatedLastRunContext for each index
        for (indexName in updatedLastRunContext.keys) {
            for (fanOutResponse in docLevelMonitorFanOutResponses) {
                // fanOutResponse.lastRunContexts //updatedContexts for relevant shards
                val indexLastRunContext = updatedLastRunContext[indexName] as MutableMap<String, Any>

                if (fanOutResponse.lastRunContexts.contains(indexName)) {
                    val partialUpdatedIndexLastRunContext = fanOutResponse.lastRunContexts[indexName] as MutableMap<String, Any>
                    partialUpdatedIndexLastRunContext.keys.forEach {

                        val seq_no = partialUpdatedIndexLastRunContext[it].toString().toIntOrNull()
                        if (
                            it != "shards_count" &&
                            it != "index" &&
                            seq_no != null &&
                            seq_no != SequenceNumbers.UNASSIGNED_SEQ_NO.toInt()
                        ) {
                            indexLastRunContext[it] = seq_no
                        }
                    }
                }
            }
        }
    }

    private fun initializeNewLastRunContext(
        lastRunContext: Map<String, Any>,
        monitorCtx: MonitorRunnerExecutionContext,
        index: String,
    ): Map<String, Any> {
        val count: Int = getShardsCount(monitorCtx.clusterService!!, index)
        val updatedLastRunContext = lastRunContext.toMutableMap()
        for (i: Int in 0 until count) {
            val shard = i.toString()
            updatedLastRunContext[shard] = SequenceNumbers.UNASSIGNED_SEQ_NO.toString()
        }
        return updatedLastRunContext
    }

    private fun validate(monitor: Monitor) {
        if (monitor.inputs.size > 1) {
            throw IOException("Only one input is supported with document-level-monitor.")
        }

        if (monitor.inputs[0].name() != DocLevelMonitorInput.DOC_LEVEL_INPUT_FIELD) {
            throw IOException("Invalid input with document-level-monitor.")
        }

        if ((monitor.inputs[0] as DocLevelMonitorInput).indices.isEmpty()) {
            throw IllegalArgumentException("DocLevelMonitorInput has no indices")
        }
    }

    // Checks if the index was created from the last execution run or when the monitor was last updated to ensure that
    // new index is monitored from the beginning of that index
    private fun createdRecently(
        monitor: Monitor,
        periodStart: Instant,
        periodEnd: Instant,
        indexMetadata: IndexMetadata,
    ): Boolean {
        val lastExecutionTime = if (periodStart == periodEnd) monitor.lastUpdateTime else periodStart
        val indexCreationDate = indexMetadata.settings.get("index.creation_date")?.toLong() ?: 0L
        return indexCreationDate > lastExecutionTime.toEpochMilli()
    }

    /**
     * Get the current max seq number of the shard. We find it by searching the last document
     *  in the primary shard.
     */
    private suspend fun getMaxSeqNo(
        client: Client,
        index: String,
        shard: String,
        nonPercolateSearchesTimeTaken: AtomicLong,
    ): Long {
        val request: SearchRequest = SearchRequest()
            .indices(index)
            .preference("_shards:$shard")
            .source(
                SearchSourceBuilder()
                    .version(true)
                    .sort("_seq_no", SortOrder.DESC)
                    .seqNoAndPrimaryTerm(true)
                    .query(QueryBuilders.matchAllQuery())
                    .size(1)
            )
        val response: SearchResponse = client.suspendUntil { client.search(request, it) }
        if (response.status() !== RestStatus.OK) {
            throw IOException("Failed to get max seq no for shard: $shard")
        }
        if (response.hits.hits.isEmpty())
            return -1L
        nonPercolateSearchesTimeTaken.getAndAdd(response.took.millis)
        return response.hits.hits[0].seqNo
    }

    private fun getShardsCount(clusterService: ClusterService, index: String): Int {
        val allShards: List<ShardRouting> = clusterService.state().routingTable().allShards(index)
        return allShards.filter { it.primary() }.size
    }

    /** 1. Fetch data per shard for given index. (only 10000 docs are fetched.
     * needs to be converted to scroll if not performant enough)
     *  2. Transform documents to conform to format required for percolate query
     *  3a. Check if docs in memory are crossing threshold defined by setting.
     *  3b. If yes, perform percolate query and update docToQueries Map with all hits from percolate queries */
    private suspend fun fetchShardDataAndMaybeExecutePercolateQueries(
        monitor: Monitor,
        monitorCtx: MonitorRunnerExecutionContext,
        indexExecutionCtx: IndexExecutionContext,
        monitorMetadata: MonitorMetadata,
        inputRunResults: MutableMap<String, MutableSet<String>>,
        docsToQueries: MutableMap<String, MutableList<String>>,
        transformedDocs: MutableList<Pair<String, TransformedDocDto>>,
        docsSizeInBytes: AtomicLong,
        monitorInputIndices: List<String>,
        concreteIndices: List<String>,
        fieldsToBeQueried: List<String>,
        nonPercolateSearchesTimeTaken: AtomicLong,
        percolateQueriesTimeTaken: AtomicLong,
        totalDocsQueried: AtomicLong,
        docTransformTimeTake: AtomicLong,
        updateLastRunContext: (String, String) -> Unit,
    ) {
        val count: Int = indexExecutionCtx.updatedLastRunContext["shards_count"] as Int
        for (i: Int in 0 until count) {
            val shard = i.toString()
            try {
                val prevSeqNo = indexExecutionCtx.lastRunContext[shard].toString().toLongOrNull()
                val from = prevSeqNo ?: SequenceNumbers.NO_OPS_PERFORMED
                var to: Long = Long.MAX_VALUE
                while (to >= from) {
                    val hits: SearchHits = searchShard(
                        monitorCtx,
                        indexExecutionCtx.concreteIndexName,
                        shard,
                        from,
                        to,
                        indexExecutionCtx.docIds,
                        fieldsToBeQueried,
                        nonPercolateSearchesTimeTaken
                    )
                    if (hits.hits.isEmpty()) {
                        updateLastRunContext(shard, (prevSeqNo ?: SequenceNumbers.NO_OPS_PERFORMED).toString())
                        break
                    }
                    if (to == Long.MAX_VALUE) { // max sequence number of shard needs to be computed

                        updateLastRunContext(shard, hits.hits[0].seqNo.toString())
                        to = hits.hits[0].seqNo - 10000L
                    } else {
                        to -= 10000L
                    }
                    val startTime = System.currentTimeMillis()
                    transformedDocs.addAll(
                        transformSearchHitsAndReconstructDocs(
                            hits,
                            indexExecutionCtx.indexName,
                            indexExecutionCtx.concreteIndexName,
                            monitor.id,
                            indexExecutionCtx.conflictingFields,
                            docsSizeInBytes
                        )
                    )
                    if (
                        transformedDocs.isNotEmpty() &&
                        shouldPerformPercolateQueryAndFlushInMemoryDocs(
                            docsSizeInBytes,
                            transformedDocs.size,
                            monitorCtx
                        )
                    ) {
                        performPercolateQueryAndResetCounters(
                            monitorCtx,
                            transformedDocs,
                            docsSizeInBytes,
                            monitor,
                            monitorMetadata,
                            monitorInputIndices,
                            concreteIndices,
                            inputRunResults,
                            docsToQueries,
                            percolateQueriesTimeTaken,
                            totalDocsQueried
                        )
                    }
                    docTransformTimeTake.getAndAdd(System.currentTimeMillis() - startTime)
                }
            } catch (e: Exception) {
                logger.error(
                    "Monitor ${monitor.id} :" +
                        "Failed to run fetch data from shard [$shard] of index [${indexExecutionCtx.concreteIndexName}]. " +
                        "Error: ${e.message}",
                    e
                )
                if (e is IndexClosedException) {
                    throw e
                }
            }
        }
    }

    private fun shouldPerformPercolateQueryAndFlushInMemoryDocs(
        docsSizeInBytes: AtomicLong,
        numDocs: Int,
        monitorCtx: MonitorRunnerExecutionContext,
    ): Boolean {
        return isInMemoryDocsSizeExceedingMemoryLimit(docsSizeInBytes.get(), monitorCtx) ||
            isInMemoryNumDocsExceedingMaxDocsPerPercolateQueryLimit(numDocs, monitorCtx)
    }

    private suspend fun performPercolateQueryAndResetCounters(
        monitorCtx: MonitorRunnerExecutionContext,
        transformedDocs: MutableList<Pair<String, TransformedDocDto>>,
        docsSizeInBytes: AtomicLong,
        monitor: Monitor,
        monitorMetadata: MonitorMetadata,
        monitorInputIndices: List<String>,
        concreteIndices: List<String>,
        inputRunResults: MutableMap<String, MutableSet<String>>,
        docsToQueries: MutableMap<String, MutableList<String>>,
        percolateQueriesTimeTaken: AtomicLong,
        totalDocsQueried: AtomicLong,
    ) {
        try {
            val percolateQueryResponseHits = runPercolateQueryOnTransformedDocs(
                monitorCtx,
                transformedDocs,
                monitor,
                monitorMetadata,
                concreteIndices,
                monitorInputIndices,
                percolateQueriesTimeTaken
            )

            percolateQueryResponseHits.forEach { hit ->
                var id = hit.id
                concreteIndices.forEach { id = id.replace("_${it}_${monitor.id}", "") }
                monitorInputIndices.forEach { id = id.replace("_${it}_${monitor.id}", "") }
                val docIndices = hit.field("_percolator_document_slot").values.map { it.toString().toInt() }
                docIndices.forEach { idx ->
                    val docIndex = "${transformedDocs[idx].first}|${transformedDocs[idx].second.concreteIndexName}"
                    inputRunResults.getOrPut(id) { mutableSetOf() }.add(docIndex)
                    docsToQueries.getOrPut(docIndex) { mutableListOf() }.add(id)
                }
            }
            totalDocsQueried.getAndAdd(transformedDocs.size.toLong())
        } finally { // no catch block because exception is caught and handled in runMonitor() class
            transformedDocs.clear()
            docsSizeInBytes.set(0)
        }
    }

    /** Executes search query on given shard of given index to fetch docs with sequence number greater than prevSeqNo.
     * This method hence fetches only docs from shard which haven't been queried before
     */
    private suspend fun searchShard(
        monitorCtx: MonitorRunnerExecutionContext,
        index: String,
        shard: String,
        prevSeqNo: Long?,
        maxSeqNo: Long,
        docIds: List<String>? = null,
        fieldsToFetch: List<String>,
        nonPercolateSearchesTimeTaken: AtomicLong,
    ): SearchHits {
        if (prevSeqNo?.equals(maxSeqNo) == true && maxSeqNo != 0L) {
            return SearchHits.empty()
        }
        val boolQueryBuilder = BoolQueryBuilder()
        boolQueryBuilder.filter(QueryBuilders.rangeQuery("_seq_no").gt(prevSeqNo).lte(maxSeqNo))

        if (!docIds.isNullOrEmpty()) {
            boolQueryBuilder.filter(QueryBuilders.termsQuery("_id", docIds))
        }

        val request: SearchRequest = SearchRequest()
            .indices(index)
            .preference("_shards:$shard")
            .source(
                SearchSourceBuilder()
                    .version(true)
                    .sort("_seq_no", SortOrder.DESC)
                    .seqNoAndPrimaryTerm(true)
                    .query(boolQueryBuilder)
                    .size(10000) // fixme: use scroll to ensure all docs are covered, when number of queryable docs are greater than 10k
            )

        if (DOC_LEVEL_MONITOR_FETCH_ONLY_QUERY_FIELDS_ENABLED.get(monitorCtx.settings) && fieldsToFetch.isNotEmpty()) {
            request.source().fetchSource(false)
            for (field in fieldsToFetch) {
                request.source().fetchField(field)
            }
        }
        val response: SearchResponse = monitorCtx.client!!.suspendUntil { monitorCtx.client!!.search(request, it) }
        if (response.status() !== RestStatus.OK) {
            throw IOException("Failed to search shard: [$shard] in index [$index]. Response status is ${response.status()}")
        }
        nonPercolateSearchesTimeTaken.getAndAdd(response.took.millis)
        return response.hits
    }

    /** Executes percolate query on the docs against the monitor's query index and return the hits from the search response*/
    private suspend fun runPercolateQueryOnTransformedDocs(
        monitorCtx: MonitorRunnerExecutionContext,
        docs: MutableList<Pair<String, TransformedDocDto>>,
        monitor: Monitor,
        monitorMetadata: MonitorMetadata,
        concreteIndices: List<String>,
        monitorInputIndices: List<String>,
        percolateQueriesTimeTaken: AtomicLong,
    ): SearchHits {
        val indices = docs.stream().map { it.second.indexName }.distinct().collect(Collectors.toList())
        val boolQueryBuilder = BoolQueryBuilder().must(buildShouldClausesOverPerIndexMatchQueries(indices))
        val percolateQueryBuilder =
            PercolateQueryBuilderExt("query", docs.map { it.second.docSource }, XContentType.JSON)
        if (monitor.id.isNotEmpty()) {
            boolQueryBuilder.must(QueryBuilders.matchQuery("monitor_id", monitor.id).operator(Operator.AND))
        }
        boolQueryBuilder.filter(percolateQueryBuilder)
        val queryIndices =
            docs.map { monitorMetadata.sourceToQueryIndexMapping[it.second.indexName + monitor.id] }.distinct()
        if (queryIndices.isEmpty()) {
            val message =
                "Monitor ${monitor.id}: Failed to resolve query Indices from source indices during monitor execution!" +
                    " sourceIndices: $monitorInputIndices"
            logger.error(message)
            throw AlertingException.wrap(
                OpenSearchStatusException(message, RestStatus.INTERNAL_SERVER_ERROR)
            )
        }

        val searchRequest =
            SearchRequest().indices(*queryIndices.toTypedArray())
        val searchSourceBuilder = SearchSourceBuilder()
        searchSourceBuilder.query(boolQueryBuilder)
        searchRequest.source(searchSourceBuilder)
        logger.debug(
            "Monitor ${monitor.id}: " +
                "Executing percolate query for docs from source indices " +
                "$monitorInputIndices against query index $queryIndices"
        )
        var response: SearchResponse
        try {
            response = monitorCtx.client!!.suspendUntil {
                monitorCtx.client!!.execute(SearchAction.INSTANCE, searchRequest, it)
            }
        } catch (e: Exception) {
            throw IllegalStateException(
                "Monitor ${monitor.id}:" +
                    " Failed to run percolate search for sourceIndex [${concreteIndices.joinToString()}] " +
                    "and queryIndex [${queryIndices.joinToString()}] for ${docs.size} document(s)",
                e
            )
        }

        if (response.status() !== RestStatus.OK) {
            throw IOException(
                "Monitor ${monitor.id}: Failed to search percolate index: ${queryIndices.joinToString()}. " +
                    "Response status is ${response.status()}"
            )
        }
        logger.error("Monitor ${monitor.id} PERF_DEBUG: Percolate query time taken millis = ${response.took}")
        logger.error("Monitor ${monitor.id} PERF_DEBUG: Percolate query response = $response")
        percolateQueriesTimeTaken.getAndAdd(response.took.millis)
        return response.hits
    }

    /** we cannot use terms query because `index` field's mapping is of type TEXT and not keyword. Refer doc-level-queries.json*/
    private fun buildShouldClausesOverPerIndexMatchQueries(indices: List<String>): BoolQueryBuilder {
        val boolQueryBuilder = QueryBuilders.boolQuery()
        indices.forEach { boolQueryBuilder.should(QueryBuilders.matchQuery("index", it)) }
        return boolQueryBuilder
    }

    /** Transform field names and index names in all the search hits to format required to run percolate search against them.
     * Hits are transformed using method transformDocumentFieldNames() */
    private fun transformSearchHitsAndReconstructDocs(
        hits: SearchHits,
        index: String,
        concreteIndex: String,
        monitorId: String,
        conflictingFields: List<String>,
        docsSizeInBytes: AtomicLong,
    ): List<Pair<String, TransformedDocDto>> {
        return hits.mapNotNull(fun(hit: SearchHit): Pair<String, TransformedDocDto>? {
            try {
                val sourceMap = if (hit.hasSource()) {
                    hit.sourceAsMap
                } else {
                    constructSourceMapFromFieldsInHit(hit)
                }
                transformDocumentFieldNames(
                    sourceMap,
                    conflictingFields,
                    "_${index}_$monitorId",
                    "_${concreteIndex}_$monitorId",
                    ""
                )
                var xContentBuilder = XContentFactory.jsonBuilder().map(sourceMap)
                val sourceRef = BytesReference.bytes(xContentBuilder)
                docsSizeInBytes.getAndAdd(sourceRef.ramBytesUsed())
                return Pair(hit.id, TransformedDocDto(index, concreteIndex, hit.id, sourceRef))
            } catch (e: Exception) {
                logger.error("Monitor $monitorId: Failed to transform payload $hit for percolate query", e)
                // skip any document which we fail to transform because we anyway won't be able to run percolate queries on them.
                return null
            }
        })
    }

    private fun constructSourceMapFromFieldsInHit(hit: SearchHit): MutableMap<String, Any> {
        if (hit.fields == null)
            return mutableMapOf()
        val sourceMap: MutableMap<String, Any> = mutableMapOf()
        for (field in hit.fields) {
            if (field.value.values != null && field.value.values.isNotEmpty())
                if (field.value.values.size == 1) {
                    sourceMap[field.key] = field.value.values[0]
                } else sourceMap[field.key] = field.value.values
        }
        return sourceMap
    }

    /**
     * Traverses document fields in leaves recursively and appends [fieldNameSuffixIndex] to field names with same names
     * but different mappings & [fieldNameSuffixPattern] to field names which have unique names.
     *
     * Example for index name is my_log_index and Monitor ID is TReewWdsf2gdJFV:
     * {                         {
     *   "a": {                     "a": {
     *     "b": 1234      ---->       "b_my_log_index_TReewWdsf2gdJFV": 1234
     *   }                          }
     * }
     *
     * @param jsonAsMap               Input JSON (as Map)
     * @param fieldNameSuffix         Field suffix which is appended to existing field name
     */
    private fun transformDocumentFieldNames(
        jsonAsMap: MutableMap<String, Any>,
        conflictingFields: List<String>,
        fieldNameSuffixPattern: String,
        fieldNameSuffixIndex: String,
        fieldNamePrefix: String,
    ) {
        val tempMap = mutableMapOf<String, Any>()
        val it: MutableIterator<Map.Entry<String, Any>> = jsonAsMap.entries.iterator()
        while (it.hasNext()) {
            val entry = it.next()
            if (entry.value is Map<*, *>) {
                transformDocumentFieldNames(
                    entry.value as MutableMap<String, Any>,
                    conflictingFields,
                    fieldNameSuffixPattern,
                    fieldNameSuffixIndex,
                    if (fieldNamePrefix == "") entry.key else "$fieldNamePrefix.${entry.key}"
                )
            } else if (!entry.key.endsWith(fieldNameSuffixPattern) && !entry.key.endsWith(fieldNameSuffixIndex)) {
                var alreadyReplaced = false
                conflictingFields.forEach { conflictingField ->
                    if (conflictingField == "$fieldNamePrefix.${entry.key}" || (fieldNamePrefix == "" && conflictingField == entry.key)) {
                        tempMap["${entry.key}$fieldNameSuffixIndex"] = entry.value
                        it.remove()
                        alreadyReplaced = true
                    }
                }
                if (!alreadyReplaced) {
                    tempMap["${entry.key}$fieldNameSuffixPattern"] = entry.value
                    it.remove()
                }
            }
        }
        jsonAsMap.putAll(tempMap)
    }

    /**
     * Returns true, if the docs fetched from shards thus far amount to less than threshold
     * amount of percentage (default:10. setting is dynamic and configurable) of the total heap size or not.
     *
     */
    private fun isInMemoryDocsSizeExceedingMemoryLimit(
        docsBytesSize: Long,
        monitorCtx: MonitorRunnerExecutionContext,
    ): Boolean {
        var thresholdPercentage = monitorCtx.percQueryDocsSizeMemoryPercentageLimit
        val heapMaxBytes = monitorCtx.jvmStats!!.mem.heapMax.bytes
        val thresholdBytes = (thresholdPercentage.toDouble() / 100.0) * heapMaxBytes

        return docsBytesSize > thresholdBytes
    }

    private fun isInMemoryNumDocsExceedingMaxDocsPerPercolateQueryLimit(
        numDocs: Int,
        monitorCtx: MonitorRunnerExecutionContext,
    ): Boolean {
        var maxNumDocsThreshold = monitorCtx.percQueryMaxNumDocsInMemory
        return numDocs >= maxNumDocsThreshold
    }

    private suspend fun getNodes(monitorCtx: MonitorRunnerExecutionContext): MutableMap<String, DiscoveryNode> {
        return monitorCtx.clusterService!!.state().nodes.dataNodes
    }

    private fun distributeShards(
        monitorCtx: MonitorRunnerExecutionContext,
        allNodes: List<String>,
        shards: List<String>,
        index: String,
    ): Map<String, MutableSet<ShardId>> {

        val totalShards = shards.size
        val numFanOutNodes = allNodes.size.coerceAtMost((totalShards + 1) / 2)
        val totalNodes = monitorCtx.totalNodesFanOut.coerceAtMost(numFanOutNodes)
        val shardsPerNode = totalShards / totalNodes
        var shardsRemaining = totalShards % totalNodes

        val shardIdList = shards.map {
            ShardId(monitorCtx.clusterService!!.state().metadata.index(index).index, it.toInt())
        }
        val nodes = allNodes.subList(0, totalNodes)

        val nodeShardAssignments = mutableMapOf<String, MutableSet<ShardId>>()
        var idx = 0
        for (node in nodes) {
            val nodeShardAssignment = mutableSetOf<ShardId>()
            for (i in 1..shardsPerNode) {
                nodeShardAssignment.add(shardIdList[idx++])
            }
            nodeShardAssignments[node] = nodeShardAssignment
        }

        for (node in nodes) {
            if (shardsRemaining == 0) {
                break
            }
            nodeShardAssignments[node]!!.add(shardIdList[idx++])
            --shardsRemaining
        }
        return nodeShardAssignments
    }

    /**
     * POJO holding information about each doc's concrete index, id, input index pattern/alias/datastream name
     * and doc source. A list of these POJOs would be passed to percolate query execution logic.
     */
    private data class TransformedDocDto(
        var indexName: String,
        var concreteIndexName: String,
        var docId: String,
        var docSource: BytesReference,
    )
}
