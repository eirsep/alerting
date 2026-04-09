# Task 5: Bucket-Level Trigger — Standard bucket_selector Query Builder

## Project
- Repo: `/Users/snistala/oasis/opensearch/alerting`
- Language: Kotlin
- Build: `./gradlew build`
- Branch: `feat/bucket-level-trigger`

## Objective
Build a utility that constructs a standard `bucket_selector` pipeline aggregation from a `BucketLevelTrigger`'s condition fields, replacing the custom `BucketSelectorExt` approach for multi-tenant evaluation.

## Why
`BucketSelectorExt` is a custom plugin aggregation that won't be recognized on user clusters (e.g., AOSS). Standard `bucket_selector` is natively supported and removes non-matching buckets from the response — remaining buckets = triggered buckets.

## Key Types
- `BucketLevelTrigger` (commons): has `bucketSelector: BucketSelectorExtAggregationBuilder` with fields:
  - `parentBucketPath: String` — path to parent agg (e.g., `"composite_agg"`)
  - `bucketsPathsMap: Map<String, String>` — maps param names to agg paths (e.g., `"docCount" to "_count"`)
  - `script: Script` — Painless condition script
  - `filter: BucketSelectorExtFilter?` — optional include/exclude filter (handled in Task 8)
- `BucketSelectorPipelineAggregationBuilder` (OpenSearch core): standard `bucket_selector` pipeline agg
- `SearchSourceBuilder`: the query being built
- `AggregationPath`: utility for parsing dot-separated agg paths

## Current Flow (BucketSelectorExt)
1. `AggregationQueryRewriter.rewriteQuery()` calls `query.aggregation(trigger.bucketSelector)` — adds `BucketSelectorExt` as a sibling pipeline agg
2. The custom aggregator runs server-side, returns `bucket_indices` and `parent_bucket_path`
3. `TriggerService.runBucketLevelTrigger()` reads `bucket_indices` from response to find matching buckets

## New Flow (standard bucket_selector)
1. `BucketSelectorQueryBuilder.injectBucketSelector()` walks the agg tree to find the parent agg
2. Adds a standard `BucketSelectorPipelineAggregationBuilder` as a **sub-agg** of the parent
3. OpenSearch natively filters out non-matching buckets
4. Remaining buckets in response = triggered buckets (handled in Task 6)

## Patterns
- Existing agg tree walking: `AggregationQueryRewriter.rewriteQuery()` lines walking `parentBucketPath`
- New file location: `alerting/src/main/kotlin/org/opensearch/alerting/util/BucketSelectorQueryBuilder.kt`
- Test location: `alerting/src/test/kotlin/org/opensearch/alerting/util/BucketSelectorQueryBuilderTests.kt`

## Dependencies
- `org.opensearch.search.aggregations.PipelineAggregatorBuilders.bucketSelector()`
- `org.opensearch.search.aggregations.support.AggregationPath`
