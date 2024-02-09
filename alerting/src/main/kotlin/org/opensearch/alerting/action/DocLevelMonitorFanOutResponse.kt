/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.action

import org.opensearch.alerting.model.DocumentLevelTriggerRunResult
import org.opensearch.alerting.model.InputRunResults
import org.opensearch.alerting.model.MonitorRunResult
import org.opensearch.core.action.ActionResponse
import org.opensearch.core.common.io.stream.StreamInput
import org.opensearch.core.common.io.stream.StreamOutput
import org.opensearch.core.xcontent.ToXContent
import org.opensearch.core.xcontent.ToXContentObject
import org.opensearch.core.xcontent.XContentBuilder
import java.io.IOException

class DocLevelMonitorFanOutResponse : ActionResponse, ToXContentObject {
    val nodeId: String
    val executionId: String
    val monitorId: String
    val shardIdFailureMap: Map<String, Exception>
    val findingIds: List<String>

    // for shards not delegated to nodes sequence number would be -3 (new number shard was not queried),
    val lastRunContexts: MutableMap<String, Any> // partial
    val inputResults: InputRunResults // partial
    val triggerResults: Map<String, DocumentLevelTriggerRunResult> // partial

    @Throws(IOException::class)
    constructor(sin: StreamInput) : this(
        nodeId = sin.readString(),
        executionId = sin.readString(),
        monitorId = sin.readString(),
        shardIdFailureMap = sin.readMap() as Map<String, Exception>,
        findingIds = sin.readStringList(),
        lastRunContexts = sin.readMap()!! as MutableMap<String, Any>,
        inputResults = InputRunResults.readFrom(sin),
        triggerResults = MonitorRunResult.suppressWarning(sin.readMap()) as Map<String, DocumentLevelTriggerRunResult> // triggerResults
    )

    constructor(
        nodeId: String,
        executionId: String,
        monitorId: String,
        shardIdFailureMap: Map<String, Exception>,
        findingIds: List<String>,
        lastRunContexts: MutableMap<String, Any>,
        inputResults: InputRunResults = InputRunResults(), // partial,
        triggerResults: Map<String, DocumentLevelTriggerRunResult> = mapOf(),
    ) : super() {
        this.nodeId = nodeId
        this.executionId = executionId
        this.monitorId = monitorId
        this.shardIdFailureMap = shardIdFailureMap
        this.findingIds = findingIds
        this.lastRunContexts = lastRunContexts
        this.inputResults = inputResults
        this.triggerResults = triggerResults
    }

    @Throws(IOException::class)
    override fun writeTo(out: StreamOutput) {
        out.writeString(nodeId)
        out.writeString(executionId)
        out.writeString(monitorId)
        out.writeMap(shardIdFailureMap)
        out.writeStringCollection(findingIds)
        out.writeMap(lastRunContexts)
        inputResults.writeTo(out)
        out.writeMap(triggerResults)
    }

    @Throws(IOException::class)
    override fun toXContent(builder: XContentBuilder, params: ToXContent.Params): XContentBuilder {
        builder.startObject()
            .field("last_run_contexts", lastRunContexts)
            .endObject()
        return builder
    }
}
