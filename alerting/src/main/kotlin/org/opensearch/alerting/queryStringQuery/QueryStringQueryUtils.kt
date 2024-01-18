package org.opensearch.alerting.queryStringQuery

import org.apache.logging.log4j.LogManager
import org.apache.lucene.queryparser.classic.ParseException
import org.apache.lucene.queryparser.classic.QueryParser
import org.opensearch.common.regex.Regex
import org.opensearch.common.xcontent.LoggingDeprecationHandler
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.index.analysis.NamedAnalyzer
import org.opensearch.index.query.QueryBuilder
import org.opensearch.index.query.QueryShardException
import org.opensearch.index.query.QueryStringQueryBuilder
import org.opensearch.index.query.support.QueryParsers
import org.opensearch.index.search.QueryParserHelper

private val log = LogManager.getLogger(QueryStringQueryUtils::class.java)

object QueryStringQueryUtils {

    @Suppress("ComplexMethod", "LongMethod", "ThrowsCount", "EmptyCatchBlock")
    fun extractFieldsFromQueries(queryBuilder: QueryBuilder, concreteIndexName: String): List<String> {
        try {
            val context = QueryShardContextFactory.createShardContext(concreteIndexName)
            val qsqBuilder = queryBuilder as QueryStringQueryBuilder
            val rewrittenQueryString =
                if (qsqBuilder.escape()) QueryParser.escape(qsqBuilder.queryString()) else qsqBuilder.queryString()
            val queryParser: QueryStringQueryParserExt
            val isLenient: Boolean =
                if (qsqBuilder.lenient() == null) context.queryStringLenient() else qsqBuilder.lenient()
            if (qsqBuilder.defaultField() != null) {
                if (Regex.isMatchAllPattern(qsqBuilder.defaultField())) {
                    queryParser =
                        QueryStringQueryParserExt(context, if (qsqBuilder.lenient() == null) true else qsqBuilder.lenient())
                } else if (Regex.isSimpleMatchPattern(qsqBuilder.defaultField())) {
                    queryParser = QueryStringQueryParserExt(context, qsqBuilder.defaultField(), isLenient)
                } else {
                    queryParser = QueryStringQueryParserExt(context, qsqBuilder.defaultField(), isLenient)
                }
            } else if (qsqBuilder.fields().size > 0) {
                val resolvedFields = QueryParserHelper.resolveMappingFields(context, qsqBuilder.fields())
                queryParser = if (QueryParserHelper.hasAllFieldsWildcard(qsqBuilder.fields().keys)) {
                    QueryStringQueryParserExt(
                        context,
                        resolvedFields,
                        if (qsqBuilder.lenient() == null) true else qsqBuilder.lenient()
                    )
                } else {
                    QueryStringQueryParserExt(context, resolvedFields, isLenient)
                }
            } else {
                val defaultFields: List<String> = context.defaultFields()
                queryParser = if (QueryParserHelper.hasAllFieldsWildcard(defaultFields)) {
                    QueryStringQueryParserExt(context, if (qsqBuilder.lenient() == null) true else qsqBuilder.lenient())
                } else {
                    val resolvedFields = QueryParserHelper.resolveMappingFields(
                        context,
                        QueryParserHelper.parseFieldsAndWeights(defaultFields)
                    )
                    QueryStringQueryParserExt(context, resolvedFields, isLenient)
                }
            }

            if (qsqBuilder.analyzer() != null) {
                val namedAnalyzer: NamedAnalyzer = context.getIndexAnalyzers().get(qsqBuilder.analyzer())
                    ?: throw QueryShardException(context, "[query_string] analyzer [$qsqBuilder.analyzer] not found")
                queryParser.setForceAnalyzer(namedAnalyzer)
            }

            if (qsqBuilder.quoteAnalyzer() != null) {
                val forceQuoteAnalyzer: NamedAnalyzer = context.getIndexAnalyzers().get(qsqBuilder.quoteAnalyzer())
                    ?: throw QueryShardException(
                        context,
                        "[query_string] quote_analyzer [$qsqBuilder.quoteAnalyzer] not found"
                    )
                queryParser.setForceQuoteAnalyzer(forceQuoteAnalyzer)
            }

            queryParser.defaultOperator = qsqBuilder.defaultOperator().toQueryParserOperator()
            // TODO can we extract this somehow? There's no getter for this
            queryParser.setType(QueryStringQueryBuilder.DEFAULT_TYPE)
            if (qsqBuilder.tieBreaker() != null) {
                queryParser.setGroupTieBreaker(qsqBuilder.tieBreaker())
            } else {
                queryParser.setGroupTieBreaker(QueryStringQueryBuilder.DEFAULT_TYPE.tieBreaker())
            }
            queryParser.phraseSlop = qsqBuilder.phraseSlop()
            queryParser.setQuoteFieldSuffix(qsqBuilder.quoteFieldSuffix())
            queryParser.allowLeadingWildcard =
                if (qsqBuilder.allowLeadingWildcard() == null) context.queryStringAllowLeadingWildcard()
                else qsqBuilder.allowLeadingWildcard()
            queryParser.setAnalyzeWildcard(
                if (qsqBuilder.analyzeWildcard() == null) context.queryStringAnalyzeWildcard()
                else qsqBuilder.analyzeWildcard()
            )
            queryParser.enablePositionIncrements = qsqBuilder.enablePositionIncrements()
            queryParser.setFuzziness(qsqBuilder.fuzziness())
            queryParser.fuzzyPrefixLength = qsqBuilder.fuzzyPrefixLength()
            queryParser.setFuzzyMaxExpansions(qsqBuilder.fuzzyMaxExpansions())
            queryParser.setFuzzyRewriteMethod(
                QueryParsers.parseRewriteMethod(
                    qsqBuilder.fuzzyRewrite(),
                    LoggingDeprecationHandler.INSTANCE
                )
            )
            queryParser.multiTermRewriteMethod =
                QueryParsers.parseRewriteMethod(qsqBuilder.rewrite(), LoggingDeprecationHandler.INSTANCE)
            queryParser.setTimeZone(qsqBuilder.timeZone())
            queryParser.determinizeWorkLimit = qsqBuilder.maxDeterminizedStates()
            queryParser.autoGenerateMultiTermSynonymsPhraseQuery = qsqBuilder.autoGenerateSynonymsPhraseQuery()
            queryParser.setFuzzyTranspositions(qsqBuilder.fuzzyTranspositions())

            try {
                queryParser.parse(rewrittenQueryString)
            } catch (e: ParseException) {
                throw IllegalArgumentException("Failed to parse query [" + qsqBuilder.queryString() + "]", e)
            }
            // Return discovered fields
            return queryParser.discoveredFields
        } catch (e: Exception) {
            log.error(
                "Failure in extracting fields from $queryBuilder for index $concreteIndexName", e
            )
            return listOf()
        }
    }

    /* extracts fields mentioned in the doc level queries which are in queryStringQuery format.
       if an empty list is returned we will query all fields as there would be possibly be a wildcard query which
       queries all fields.
     */
    fun extractFieldsFromQueries(queries: List<DocLevelQuery>, concreteIndexName: String): List<String> {
        val fields: MutableSet<String> = mutableSetOf()
        for (query in queries) {
            val fieldsForQuery = extractFieldsFromQueries(QueryStringQueryBuilder(query.query), concreteIndexName)
            if (fieldsForQuery.isEmpty()) // queries all fields
                return emptyList()
            fields.addAll(fieldsForQuery)
        }
        return fields.toList()
    }
}
