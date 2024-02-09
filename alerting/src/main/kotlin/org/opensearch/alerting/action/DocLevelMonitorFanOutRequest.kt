/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.action

import org.opensearch.action.ActionRequest
import org.opensearch.action.ActionRequestValidationException
import org.opensearch.alerting.model.IndexExecutionContext
import org.opensearch.alerting.model.MonitorMetadata
import org.opensearch.alerting.workflow.WorkflowRunContext
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.core.common.io.stream.StreamInput
import org.opensearch.core.common.io.stream.StreamOutput
import org.opensearch.core.index.shard.ShardId
import org.opensearch.core.xcontent.ToXContent
import org.opensearch.core.xcontent.ToXContentObject
import org.opensearch.core.xcontent.XContentBuilder
import java.io.IOException

class DocLevelMonitorFanOutRequest : ActionRequest, ToXContentObject {

    val nodeId: String
    val monitor: Monitor
    val monitorMetadata: MonitorMetadata
    val executionId: String
    val indexExecutionContexts: List<IndexExecutionContext>
    val shardIds: List<ShardId>
    val workflowRunContext: WorkflowRunContext?

    constructor(
        nodeId: String,
        monitor: Monitor,
        monitorMetadata: MonitorMetadata,
        executionId: String,
        indexExecutionContexts: List<IndexExecutionContext>,
        shardIds: List<ShardId>,
        workflowRunContext: WorkflowRunContext?,
    ) : super() {
        this.nodeId = nodeId
        this.monitor = monitor
        this.monitorMetadata = monitorMetadata
        this.executionId = executionId
        this.indexExecutionContexts = indexExecutionContexts
        this.shardIds = shardIds
        this.workflowRunContext = workflowRunContext
        require(false == shardIds.isEmpty()) { }
        require(false == indexExecutionContexts.isEmpty()) { }
    }

    @Throws(IOException::class)
    constructor(sin: StreamInput) : this(
        nodeId = sin.readString(),
        monitor = Monitor.readFrom(sin)!!,
        monitorMetadata = MonitorMetadata.readFrom(sin),
        executionId = sin.readString(),
        indexExecutionContexts = sin.readList { IndexExecutionContext(sin) },
        shardIds = sin.readList(::ShardId),
        workflowRunContext = if (sin.readBoolean()) {
            WorkflowRunContext(sin)
        } else null,
    )

    @Throws(IOException::class)
    override fun writeTo(out: StreamOutput) {
        out.writeString(nodeId)
        monitor.writeTo(out)
        monitorMetadata.writeTo(out)
        out.writeString(executionId)
        out.writeCollection(indexExecutionContexts)
        out.writeCollection(shardIds)
        out.writeBoolean(workflowRunContext != null)
        workflowRunContext?.writeTo(out)
    }

    override fun validate(): ActionRequestValidationException? {
        var actionValidationException: ActionRequestValidationException? = null
        if (shardIds.isEmpty()) {
            actionValidationException = ActionRequestValidationException()
            actionValidationException.addValidationError("shard_ids is null or empty")
        }
        if (indexExecutionContexts.isEmpty()) {
            if (actionValidationException == null)
                actionValidationException = ActionRequestValidationException()
            actionValidationException.addValidationError("index_execution_contexts is null or empty")
        }
        return actionValidationException
    }

    @Throws(IOException::class)
    override fun toXContent(builder: XContentBuilder, params: ToXContent.Params): XContentBuilder {
        builder.startObject()
            .field("node_id", nodeId)
            .field("monitor", monitor)
            .field("execution_id", executionId)
            .field("index_execution_contexts", indexExecutionContexts)
            .field("shard_ids", shardIds)
            .field("workflow_run_context", workflowRunContext)
        return builder.endObject()
    }
}
