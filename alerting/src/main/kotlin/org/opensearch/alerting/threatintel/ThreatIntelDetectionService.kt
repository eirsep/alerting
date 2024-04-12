package org.opensearch.alerting.threatintel

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.apache.logging.log4j.LogManager
import org.opensearch.action.DocWriteRequest
import org.opensearch.action.admin.indices.refresh.RefreshAction
import org.opensearch.action.admin.indices.refresh.RefreshRequest
import org.opensearch.action.admin.indices.refresh.RefreshResponse
import org.opensearch.action.bulk.BulkRequest
import org.opensearch.action.bulk.BulkResponse
import org.opensearch.action.index.IndexRequest
import org.opensearch.action.search.SearchRequest
import org.opensearch.action.search.SearchResponse
import org.opensearch.action.support.GroupedActionListener
import org.opensearch.alerting.opensearchapi.suspendUntil
import org.opensearch.alerting.transport.TransportDocLevelMonitorFanOutAction
import org.opensearch.client.Client
import org.opensearch.common.document.DocumentField
import org.opensearch.common.xcontent.XContentType
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.commons.alerting.model.Finding
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.util.string
import org.opensearch.core.xcontent.NamedXContentRegistry
import org.opensearch.core.xcontent.ToXContent
import org.opensearch.core.xcontent.XContentBuilder
import org.opensearch.index.query.QueryBuilders
import org.opensearch.search.SearchHit
import java.time.Instant
import java.util.UUID
import java.util.stream.Collectors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import kotlin.math.min

private val log = LogManager.getLogger(TransportDocLevelMonitorFanOutAction::class.java)
private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)

// todo logging n try-catch
class ThreatIntelDetectionService(
    val client: Client,
    val xContentRegistry: NamedXContentRegistry,
) {

    val BATCH_SIZE = 65536
    val IOC_FIELD_NAME = "ioc"
    suspend fun scanDataAgainstThreatIntel(monitor: Monitor, threatIntelIndices: List<String>, hits: List<SearchHit>) {
        val start = System.currentTimeMillis()
        try {
            val stringList = buildTerms(monitor, hits)
            log.error("TI_DEBUG: num iocs in queried data: ${stringList.size}")
            searchTermsOnIndices(monitor, stringList.toList(), threatIntelIndices)
        } catch (e: Exception) {
            log.error("TI_DEBUG: failed to scan data against threat intel", e)
        } finally {
            val end = System.currentTimeMillis()
            if (hits.isNotEmpty() && threatIntelIndices.isNotEmpty()) {
                val l = end - start
                log.error("TI_DEBUG: TOTAL TIME TAKEN for Threat intel matching for ${hits.size} is $l millis")
            }
        }
    }

    private fun buildTerms(monitor: Monitor, hits: List<SearchHit>): MutableSet<String> {
        try {
            val input = monitor.inputs[0] as DocLevelMonitorInput
            val iocFieldNames = input.iocFieldNames
            val iocsInData = mutableSetOf<String>()
            for (hit in hits) {
                if (hit.fields.isNotEmpty()) {
                    for (entry in hit.fields.entries) {
                        if (iocFieldNames.contains(entry.key)) {
                            if (entry.value.values.isNotEmpty()) {
                                iocsInData.addAll(
                                    entry.value.values.stream().map { it.toString() }
                                        .collect(
                                            Collectors.toList()
                                        )
                                ) // fixme should we get input from customer on which specific ioc like ip or dns is present in which field
                            }
                        }
                    }
                }
            }
            return iocsInData
        } catch (e: Exception) {
            log.error("TI_DEBUG: Failed to extract IoC's from the queryable data to scan against threat intel")
            return mutableSetOf()
        }
    }

    private suspend fun searchTermsOnIndices(monitor: Monitor, iocs: List<String>, threatIntelIndices: List<String>) {
        val iocSubLists = iocs.chunkSublists(BATCH_SIZE)
        // TODO get unique values from list first
        val responses: Collection<SearchResponse> =
            suspendCoroutine { cont -> // todo implement a listener that tolerates multiple exceptions
                val groupedListener = GroupedActionListener(
                    object : org.opensearch.core.action.ActionListener<Collection<SearchResponse>> {
                        override fun onResponse(responses: Collection<SearchResponse>) {

                            cont.resume(responses)
                        }

                        override fun onFailure(e: Exception) {
                            if (e.cause is Exception)
                                cont.resumeWithException(e.cause as Exception)
                            else
                                cont.resumeWithException(e)
                        }
                    },
                    iocSubLists.size
                )
                // chunk all iocs from queryable data and perform terms query for matches
                // if matched return only the ioc's that matched and not the entire document
                for (iocSubList in iocSubLists) {
                    if (iocSubList.isEmpty()) continue
                    val searchRequest = SearchRequest(*threatIntelIndices.toTypedArray())
                    val queryBuilder = QueryBuilders.boolQuery()
                    queryBuilder.filter(QueryBuilders.boolQuery().must(QueryBuilders.termsQuery(IOC_FIELD_NAME, iocSubList)))
                    searchRequest.source().query(queryBuilder)
                    searchRequest.source().fetchSource(false).fetchField(IOC_FIELD_NAME)
                    client.search(searchRequest, groupedListener)
                }
            }
        val iocMatches = mutableSetOf<String>()
        for (response in responses) {
            log.error("TI_DEBUG search response took: ${response.took} millis")
            if (response.hits.hits.isEmpty()) continue
            for (hit in response.hits.hits) {
                if (hit.fields != null && hit.fields.containsKey(IOC_FIELD_NAME)) {
                    val element: DocumentField? = hit.fields[IOC_FIELD_NAME]
                    if (element!!.values.isNotEmpty())
                        iocMatches.add(element.values[0].toString())
                }
            }
        }
        log.error("TI_DEBUG num ioc matches: ${iocMatches.size}")
        createFindings(monitor, iocMatches.toList())
    }

    // Function to chunk a list into sublists of specified size
    fun <T> List<T>.chunkSublists(chunkSize: Int): List<List<T>> {
        return (0..size step chunkSize).map { subList(fromIndex = it, toIndex = min(it + chunkSize, size)) }
    }

    suspend fun createFindings(monitor: Monitor, iocMatches: List<String>) {
        val findingDocPairs = mutableListOf<Pair<String, String>>()
        val findings = mutableListOf<Finding>()
        val indexRequests = mutableListOf<IndexRequest>()
        val findingsToTriggeredQueries = mutableMapOf<String, List<DocLevelQuery>>()

        for (iocMatch in iocMatches) {
            val finding = Finding(
                id = "ioc" + UUID.randomUUID().toString(),
                relatedDocIds = listOf(iocMatch),
                correlatedDocIds = listOf(),
                monitorId = monitor.id,
                monitorName = monitor.name,
                index = (monitor.inputs[0] as DocLevelMonitorInput).indices[0],
                docLevelQueries = listOf(DocLevelQuery("threat_intel", iocMatch, emptyList(), "", emptyList())),
                timestamp = Instant.now(),
                executionId = null,
            )
            val findingStr =
                finding.toXContent(XContentBuilder.builder(XContentType.JSON.xContent()), ToXContent.EMPTY_PARAMS)
                    .string()
            log.debug("Findings: $findingStr")
            indexRequests += IndexRequest(monitor.dataSources.findingsIndex)
                .source(findingStr, XContentType.JSON)
                .id(finding.id)
                .opType(DocWriteRequest.OpType.CREATE)
        }
        bulkIndexFindings(monitor, indexRequests)
    }

    private suspend fun bulkIndexFindings(
        monitor: Monitor,
        indexRequests: List<IndexRequest>,
    ) {
        indexRequests.chunked(1000).forEach { batch ->
            val bulkResponse: BulkResponse = client.suspendUntil {
                bulk(BulkRequest().add(batch), it)
            }
            if (bulkResponse.hasFailures()) {
                bulkResponse.items.forEach { item ->
                    if (item.isFailed) {
                        log.error("Failed indexing the finding ${item.id} of monitor [${monitor.id}]")
                    }
                }
            } else {
                log.debug("[${bulkResponse.items.size}] All findings successfully indexed.")
            }
        }
        val res: RefreshResponse =
            client.suspendUntil { client.execute(RefreshAction.INSTANCE, RefreshRequest(monitor.dataSources.findingsIndex)) }
    }
}
