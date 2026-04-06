/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting

import org.opensearch.alerting.alerts.AlertIndices
import org.opensearch.alerting.settings.AlertingSettings
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtFilter
import org.opensearch.commons.alerting.model.Alert.State.ACTIVE
import org.opensearch.commons.alerting.model.Alert.State.COMPLETED
import org.opensearch.commons.alerting.model.SearchInput
import org.opensearch.index.query.QueryBuilders
import org.opensearch.script.Script
import org.opensearch.search.aggregations.bucket.composite.CompositeAggregationBuilder
import org.opensearch.search.aggregations.bucket.composite.TermsValuesSourceBuilder
import org.opensearch.search.aggregations.bucket.terms.IncludeExclude
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder
import org.opensearch.search.builder.SearchSourceBuilder
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Integration tests for bucket-level trigger evaluation with the multi-tenant trigger eval flag enabled.
 * These tests verify that standard bucket_selector injection and filtered response parsing work
 * correctly end-to-end.
 */
class RemoteBucketLevelTriggerIT : AlertingRestTestCase() {

    private val SETTING_KEY = AlertingSettings.MULTI_TENANT_TRIGGER_EVAL_ENABLED.key

    private fun enableRemoteTriggerEval() {
        client().updateSettings(SETTING_KEY, true)
    }

    private fun disableRemoteTriggerEval() {
        client().updateSettings(SETTING_KEY, false)
    }

    private fun buildCompositeInput(index: String): SearchInput {
        val query = QueryBuilders.rangeQuery("test_strict_date_time")
            .gt("{{period_end}}||-10d")
            .lte("{{period_end}}")
            .format("epoch_millis")
        val compositeSources = listOf(TermsValuesSourceBuilder("test_field").field("test_field"))
        val compositeAgg = CompositeAggregationBuilder("composite_agg", compositeSources)
        return SearchInput(indices = listOf(index), query = SearchSourceBuilder().size(0).query(query).aggregation(compositeAgg))
    }

    private fun buildTermsInput(index: String): SearchInput {
        val query = QueryBuilders.rangeQuery("test_strict_date_time")
            .gt("{{period_end}}||-10d")
            .lte("{{period_end}}")
            .format("epoch_millis")
        val termsAgg = TermsAggregationBuilder("terms_agg").field("test_field")
        return SearchInput(indices = listOf(index), query = SearchSourceBuilder().size(0).query(query).aggregation(termsAgg))
    }

    private fun buildTrigger(
        parentBucketPath: String = "composite_agg",
        script: String = "params.docCount > 0"
    ): org.opensearch.commons.alerting.model.BucketLevelTrigger {
        var trigger = randomBucketLevelTrigger()
        trigger = trigger.copy(
            bucketSelector = BucketSelectorExtAggregationBuilder(
                name = trigger.id,
                bucketsPathsMap = mapOf("docCount" to "_count"),
                script = Script(script),
                parentBucketPath = parentBucketPath,
                filter = null
            )
        )
        return trigger
    }

    // ---- Tests ----

    fun `test multi tenant bucket trigger composite agg`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            val trigger = buildTrigger(script = "params.docCount > 0")
            val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)
            assertEquals(monitor.name, output["monitor_name"])

            val triggerResult = output.objectMap("trigger_results").objectMap(trigger.id)
            @Suppress("UNCHECKED_CAST")
            val buckets = triggerResult["agg_result_buckets"] as Map<String, Any>
            assertEquals("Both buckets should match", 2, buckets.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger terms agg`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildTermsInput(testIndex)
            val trigger = buildTrigger(parentBucketPath = "terms_agg", script = "params.docCount > 1")
            val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)

            val triggerResult = output.objectMap("trigger_results").objectMap(trigger.id)
            @Suppress("UNCHECKED_CAST")
            val buckets = triggerResult["agg_result_buckets"] as Map<String, Any>
            // Only test_value_1 has docCount > 1
            assertEquals("Only one bucket should match", 1, buckets.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger alert lifecycle`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            val trigger = buildTrigger(script = "params.docCount > 0")
            val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

            // First execution — alerts created
            executeMonitor(monitor.id)
            var alerts = searchAlerts(monitor)
            assertEquals("Alerts not saved", 2, alerts.size)
            alerts.forEach { assertEquals(ACTIVE, it.state) }

            // Delete docs for one bucket
            deleteDataWithDocIds(testIndex, listOf("1", "2")) // test_value_1

            // Second execution — one alert completed
            executeMonitor(monitor.id)
            alerts = searchAlerts(monitor, AlertIndices.ALL_ALERT_INDEX_PATTERN)
            val activeAlerts = alerts.filter { it.state == ACTIVE }
            val completedAlerts = alerts.filter { it.state == COMPLETED }
            assertEquals("Incorrect number of active alerts", 1, activeAlerts.size)
            assertEquals("Incorrect number of completed alerts", 1, completedAlerts.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger no matching buckets`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1"))

            val input = buildCompositeInput(testIndex)
            val trigger = buildTrigger(script = "params.docCount > 100")
            val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)

            val triggerResult = output.objectMap("trigger_results").objectMap(trigger.id)
            @Suppress("UNCHECKED_CAST")
            val buckets = triggerResult["agg_result_buckets"] as Map<String, Any>
            assertTrue("No buckets should match", buckets.isEmpty())
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger dry run`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            val trigger = buildTrigger(script = "params.docCount > 0")
            val monitor = randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger))

            // Dry run — no alerts persisted
            val response = executeMonitor(monitor, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)

            val triggerResult = output.objectMap("trigger_results").objectMap(trigger.id)
            @Suppress("UNCHECKED_CAST")
            val buckets = triggerResult["agg_result_buckets"] as Map<String, Any>
            assertEquals(2, buckets.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger multiple triggers`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            // Different thresholds — each trigger evaluates independently via separate queries
            val trigger1 = buildTrigger(script = "params.docCount > 0") // both buckets match
            val trigger2 = buildTrigger(script = "params.docCount > 1") // only test_value_1 matches
            val monitor = createMonitor(
                randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger1, trigger2))
            )

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)
            val triggerResults = output.objectMap("trigger_results")

            @Suppress("UNCHECKED_CAST")
            val buckets1 = triggerResults.objectMap(trigger1.id)["agg_result_buckets"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            val buckets2 = triggerResults.objectMap(trigger2.id)["agg_result_buckets"] as Map<String, Any>
            assertEquals("Trigger 1 should match both buckets", 2, buckets1.size)
            assertEquals("Trigger 2 should match one bucket", 1, buckets2.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger with painless script in query`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex(
                randomAlphaOfLength(10).lowercase(),
                """
                    "properties": {
                        "test_strict_date_time": { "type": "date", "format": "strict_date_time" },
                        "test_field": { "type": "keyword" },
                        "value": { "type": "integer" }
                    }
                """
            )
            val twoMinsAgo = ZonedDateTime.now().minus(2, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS)
            val testTime = DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(twoMinsAgo)
            indexDoc(testIndex, "1", """{ "test_strict_date_time": "$testTime", "test_field": "a", "value": 10 }""")
            indexDoc(testIndex, "2", """{ "test_strict_date_time": "$testTime", "test_field": "a", "value": 20 }""")
            indexDoc(testIndex, "3", """{ "test_strict_date_time": "$testTime", "test_field": "b", "value": 5 }""")

            // Query uses a Painless script filter: only docs where value > 8
            val query = QueryBuilders.boolQuery()
                .must(
                    QueryBuilders.rangeQuery("test_strict_date_time")
                        .gt("{{period_end}}||-10d").lte("{{period_end}}").format("epoch_millis")
                )
                .filter(QueryBuilders.scriptQuery(Script("doc['value'].value > 8")))
            val compositeSources = listOf(TermsValuesSourceBuilder("test_field").field("test_field"))
            val compositeAgg = CompositeAggregationBuilder("composite_agg", compositeSources)
            val input = SearchInput(
                indices = listOf(testIndex),
                query = SearchSourceBuilder().size(0).query(query).aggregation(compositeAgg)
            )
            // Only bucket "a" survives the script filter (values 10, 20); "b" (value 5) is excluded
            val trigger = buildTrigger(script = "params.docCount > 0")
            val monitor = createMonitor(
                randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger))
            )

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)
            val triggerResult = output.objectMap("trigger_results").objectMap(trigger.id)
            @Suppress("UNCHECKED_CAST")
            val buckets = triggerResult["agg_result_buckets"] as Map<String, Any>
            assertEquals("Only bucket 'a' should survive the Painless script filter", 1, buckets.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger nested parent path`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex(
                randomAlphaOfLength(10).lowercase(),
                """
                    "properties": {
                        "test_strict_date_time": { "type": "date", "format": "strict_date_time" },
                        "host": { "type": "keyword" },
                        "status": { "type": "keyword" }
                    }
                """
            )
            val twoMinsAgo = ZonedDateTime.now().minus(2, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS)
            val testTime = DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(twoMinsAgo)
            // host_a: 3 docs (status 200, 200, 500), host_b: 1 doc (status 200)
            indexDoc(testIndex, "1", """{ "test_strict_date_time": "$testTime", "host": "host_a", "status": "200" }""")
            indexDoc(testIndex, "2", """{ "test_strict_date_time": "$testTime", "host": "host_a", "status": "200" }""")
            indexDoc(testIndex, "3", """{ "test_strict_date_time": "$testTime", "host": "host_a", "status": "500" }""")
            indexDoc(testIndex, "4", """{ "test_strict_date_time": "$testTime", "host": "host_b", "status": "200" }""")

            val query = QueryBuilders.rangeQuery("test_strict_date_time")
                .gt("{{period_end}}||-10d")
                .lte("{{period_end}}")
                .format("epoch_millis")
            // Top-level composite agg on host — this is the parentBucketPath target
            val compositeSources = listOf(TermsValuesSourceBuilder("host").field("host"))
            // Nested sub-agg: terms on status under composite
            val statusAgg = TermsAggregationBuilder("status_breakdown").field("status")
            val compositeAgg = CompositeAggregationBuilder("composite_agg", compositeSources)
                .subAggregation(statusAgg)
            val input = SearchInput(
                indices = listOf(testIndex),
                query = SearchSourceBuilder().size(0).query(query).aggregation(compositeAgg)
            )

            // Trigger A: host_a(3 docs) matches, host_b(1 doc) doesn't
            val triggerA = buildTrigger(parentBucketPath = "composite_agg", script = "params.docCount > 1")
            // Trigger B: both hosts match
            val triggerB = buildTrigger(parentBucketPath = "composite_agg", script = "params.docCount > 0")
            val monitor = createMonitor(
                randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(triggerA, triggerB))
            )

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)
            val triggerResults = output.objectMap("trigger_results")

            @Suppress("UNCHECKED_CAST")
            val bucketsA = triggerResults.objectMap(triggerA.id)["agg_result_buckets"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            val bucketsB = triggerResults.objectMap(triggerB.id)["agg_result_buckets"] as Map<String, Any>
            assertEquals("Trigger A should match only host_a", 1, bucketsA.size)
            assertEquals("Trigger B should match both hosts", 2, bucketsB.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger include exclude filter`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            // 4 buckets: test_value_1(2 docs), test_value_2(1), test_value_3(1), test_value_4(1)
            insertSampleTimeSerializedData(
                testIndex,
                listOf("test_value_1", "test_value_1", "test_value_2", "test_value_3", "test_value_4")
            )

            val input = buildCompositeInput(testIndex)
            // Trigger A: all buckets match (docCount > 0), but include filter limits to test_value_1 and test_value_2
            var triggerA = randomBucketLevelTrigger()
            triggerA = triggerA.copy(
                bucketSelector = BucketSelectorExtAggregationBuilder(
                    name = triggerA.id,
                    bucketsPathsMap = mapOf("docCount" to "_count"),
                    script = Script("params.docCount > 0"),
                    parentBucketPath = "composite_agg",
                    filter = BucketSelectorExtFilter(IncludeExclude("test_value_[12]", null))
                )
            )
            // Trigger B: all buckets match, exclude filter removes test_value_1
            var triggerB = randomBucketLevelTrigger()
            triggerB = triggerB.copy(
                bucketSelector = BucketSelectorExtAggregationBuilder(
                    name = triggerB.id,
                    bucketsPathsMap = mapOf("docCount" to "_count"),
                    script = Script("params.docCount > 0"),
                    parentBucketPath = "composite_agg",
                    filter = BucketSelectorExtFilter(IncludeExclude(null, "test_value_1"))
                )
            )
            val monitor = createMonitor(
                randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(triggerA, triggerB))
            )

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)
            val triggerResults = output.objectMap("trigger_results")

            @Suppress("UNCHECKED_CAST")
            val bucketsA = triggerResults.objectMap(triggerA.id)["agg_result_buckets"] as Map<String, Any>
            @Suppress("UNCHECKED_CAST")
            val bucketsB = triggerResults.objectMap(triggerB.id)["agg_result_buckets"] as Map<String, Any>
            // Trigger A: 4 buckets pass script, include filter keeps test_value_1 and test_value_2
            assertEquals("Trigger A should match 2 buckets after include filter", 2, bucketsA.size)
            // Trigger B: 4 buckets pass script, exclude filter removes test_value_1 → 3 remain
            assertEquals("Trigger B should match 3 buckets after exclude filter", 3, bucketsB.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger input results populated without base query`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            val trigger = buildTrigger(script = "params.docCount > 0")
            val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

            val response = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val output = entityAsMap(response)

            // Verify input_results is populated even though the base query is skipped
            @Suppress("UNCHECKED_CAST")
            val inputResults = output.objectMap("input_results")["results"] as List<Map<String, Any>>
            assertTrue("input_results should not be empty", inputResults.isNotEmpty())
            val firstResult = inputResults.first()
            assertNotNull("Aggregations should be present", firstResult["aggregations"])
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger single trigger matches flag off`() {
        val testIndex = createTestIndex()
        insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

        val input = buildCompositeInput(testIndex)
        val trigger = buildTrigger(script = "params.docCount > 1")
        val monitor = createMonitor(randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger)))

        // Execute with flag off
        client().updateSettings(SETTING_KEY, false)
        val responseOff = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
        val outputOff = entityAsMap(responseOff)
        @Suppress("UNCHECKED_CAST")
        val bucketsOff = outputOff.objectMap("trigger_results").objectMap(trigger.id)["agg_result_buckets"] as Map<String, Any>

        // Execute with flag on
        enableRemoteTriggerEval()
        try {
            val responseOn = executeMonitor(monitor.id, params = DRYRUN_MONITOR)
            val outputOn = entityAsMap(responseOn)
            @Suppress("UNCHECKED_CAST")
            val bucketsOn = outputOn.objectMap("trigger_results").objectMap(trigger.id)["agg_result_buckets"] as Map<String, Any>

            assertEquals("Single trigger should produce same bucket count", bucketsOff.size, bucketsOn.size)
            assertEquals("Only test_value_1 should match", 1, bucketsOn.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    fun `test multi tenant bucket trigger alert lifecycle without base query`() {
        enableRemoteTriggerEval()
        try {
            val testIndex = createTestIndex()
            insertSampleTimeSerializedData(testIndex, listOf("test_value_1", "test_value_1", "test_value_2"))

            val input = buildCompositeInput(testIndex)
            val trigger1 = buildTrigger(script = "params.docCount > 0") // both buckets
            val trigger2 = buildTrigger(script = "params.docCount > 1") // only test_value_1
            val monitor = createMonitor(
                randomBucketLevelMonitor(inputs = listOf(input), enabled = false, triggers = listOf(trigger1, trigger2))
            )

            // First execution — alerts created
            executeMonitor(monitor.id)
            var alerts = searchAlerts(monitor)
            val trigger1Alerts = alerts.filter { it.triggerId == trigger1.id }
            val trigger2Alerts = alerts.filter { it.triggerId == trigger2.id }
            assertEquals("Trigger 1 should have 2 alerts", 2, trigger1Alerts.size)
            assertEquals("Trigger 2 should have 1 alert", 1, trigger2Alerts.size)

            // Delete docs for test_value_1
            deleteDataWithDocIds(testIndex, listOf("1", "2"))

            // Second execution — trigger1: test_value_1 completed, test_value_2 active; trigger2: test_value_1 completed
            executeMonitor(monitor.id)
            alerts = searchAlerts(monitor, AlertIndices.ALL_ALERT_INDEX_PATTERN)
            val t1Active = alerts.filter { it.triggerId == trigger1.id && it.state == ACTIVE }
            val t1Completed = alerts.filter { it.triggerId == trigger1.id && it.state == COMPLETED }
            val t2Completed = alerts.filter { it.triggerId == trigger2.id && it.state == COMPLETED }
            assertEquals("Trigger 1 should have 1 active alert", 1, t1Active.size)
            assertEquals("Trigger 1 should have 1 completed alert", 1, t1Completed.size)
            assertEquals("Trigger 2 should have 1 completed alert", 1, t2Completed.size)
        } finally {
            disableRemoteTriggerEval()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun Map<String, Any>.objectMap(key: String): Map<String, Map<String, Any>> {
        return this[key] as Map<String, Map<String, Any>>
    }
}
