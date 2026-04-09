# Task 5 Plan

## Test Scenarios

1. **Single trigger, composite agg parent** — inject bucket_selector under `composite_agg`, verify it appears as sub-agg
2. **Single trigger, terms agg parent** — inject under `TermsAggregationBuilder`, verify sub-agg added
3. **Nested parent path** (e.g., `outer>inner`) — walk two levels, inject under inner agg
4. **Multiple triggers** — inject multiple bucket_selectors with unique names under same parent
5. **Parent agg not found** — throw `IllegalArgumentException`
6. **Preserves existing sub-aggs** — existing sub-aggs on parent are not removed

## Implementation Plan

1. Create `BucketSelectorQueryBuilder` object in `alerting/src/main/kotlin/org/opensearch/alerting/util/`
2. Single method: `injectBucketSelector(query: SearchSourceBuilder, triggers: List<BucketLevelTrigger>): SearchSourceBuilder`
3. For each trigger:
   - Parse `parentBucketPath` via `AggregationPath`
   - Walk agg tree to find parent `AggregationBuilder`
   - Add `PipelineAggregatorBuilders.bucketSelector()` as sub-agg with name `_trigger_filter_{triggerId}`
4. Return modified query
