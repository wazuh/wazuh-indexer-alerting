/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import kotlinx.coroutines.runBlocking
import org.apache.lucene.search.TotalHits
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.opensearch.Version
import org.opensearch.action.DocWriteRequest
import org.opensearch.action.bulk.BulkItemResponse
import org.opensearch.action.bulk.BulkRequest
import org.opensearch.action.bulk.BulkResponse
import org.opensearch.action.index.IndexResponse
import org.opensearch.action.search.SearchRequest
import org.opensearch.action.search.SearchResponse
import org.opensearch.action.search.ShardSearchFailure
import org.opensearch.action.support.WriteRequest.RefreshPolicy
import org.opensearch.alerting.randomDocumentLevelMonitor
import org.opensearch.cluster.ClusterName
import org.opensearch.cluster.ClusterState
import org.opensearch.cluster.metadata.AliasMetadata
import org.opensearch.cluster.metadata.IndexMetadata
import org.opensearch.cluster.metadata.Metadata
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.settings.Settings
import org.opensearch.common.unit.TimeValue
import org.opensearch.commons.alerting.model.DataSources
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.model.MonitorMetadata
import org.opensearch.core.action.ActionListener
import org.opensearch.core.index.Index
import org.opensearch.core.index.shard.ShardId
import org.opensearch.search.SearchHits
import org.opensearch.search.internal.InternalSearchResponse
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.client.Client

/** Scheduled runs skip indexing the queries of a source index while they are current. */
class IndexedQueriesTests : OpenSearchTestCase() {

    private val source = "logs"
    private val alias = ".opensearch-alerting-queries"
    private val queryIndex = "$alias-000001"
    private val query = DocLevelQuery("q1", "q1", emptyList(), "user.name:\"admin\"", emptyList(), listOf("user.name"))
    private val docIds = setOf("q1_logs_mid")

    fun `test the state is the same for the same monitor, source mappings and query index`() {
        val state = IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState())

        assertEquals(state, IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState()))
    }

    fun `test the state changes with anything the queries are built from`() {
        val base = IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState())
        val otherQuery = query.copy(query = "user.name:\"root\"")
        val variants = mapOf(
            "a query" to IndexedQueriesState.of(monitor(otherQuery), listOf(source), queryIndex, "q-uuid", clusterState()),
            "the data sources" to IndexedQueriesState.of(
                monitor(dataSources = DataSources(queryIndex = ".custom-queries", queryIndexMappingsByType = mapOf("text" to mapOf("analyzer" to "a")))),
                listOf(source), queryIndex, "q-uuid", clusterState()
            ),
            "the source mapping" to IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState(mappingVersion = 2)),
            "the source settings" to IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState(settingsVersion = 2)),
            "a recreated source index" to IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q-uuid", clusterState(sourceUuid = "s2")),
            "the concrete source indices" to IndexedQueriesState.of(monitor(), listOf(source, "other"), queryIndex, "q-uuid", clusterState()),
            "the query index" to IndexedQueriesState.of(monitor(), listOf(source), "$alias-000002", "q-uuid", clusterState()),
            "a recreated query index" to IndexedQueriesState.of(monitor(), listOf(source), queryIndex, "q2", clusterState())
        )

        variants.forEach { (change, state) -> assertNotEquals("a change of $change", base, state) }
    }

    fun `test queries are reused while their state and documents are unchanged`() {
        val (queries, client) = queries(clusterState(), docsFound = 1)
        record(queries, monitor(), clusterState())

        assertTrue(alreadyIndexed(queries, monitor(), metadata()))
        verify(client).search(any(), any())
    }

    fun `test queries are indexed again when the source mapping changed`() {
        val changed = clusterState(mappingVersion = 2)
        val (queries, client) = queries(changed, docsFound = 1)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(), metadata(), changed))
        verify(client, never()).search(any(), any())
    }

    fun `test queries are indexed again when the monitor queries changed`() {
        val (queries, _) = queries(clusterState(), docsFound = 1)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(query.copy(query = "user.name:\"root\"")), metadata()))
    }

    fun `test queries are indexed again when the query index was recreated`() {
        val recreated = clusterState(queryIndexUuid = "q2")
        val (queries, _) = queries(recreated, docsFound = 1)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(), metadata(), recreated))
    }

    fun `test queries are indexed again when their documents are gone`() {
        val (queries, client) = queries(clusterState(), docsFound = 0)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(), metadata()))
        verify(client).search(any(), any())
    }

    fun `test queries are indexed again when their documents cannot be counted`() {
        val (queries, _) = queries(clusterState(), docsFound = null)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(), metadata()))
    }

    fun `test queries are indexed when the monitor metadata does not map the source index`() {
        val (queries, _) = queries(clusterState(), docsFound = 1)
        record(queries, monitor(), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(), metadata(mapped = false)))
    }

    fun `test queries are indexed when this node never indexed them, or forgot them`() {
        val (queries, _) = queries(clusterState(), docsFound = 1)
        assertFalse(alreadyIndexed(queries, monitor(), metadata()))

        record(queries, monitor(), clusterState())
        queries.forgetIndexedQueries("mid")

        assertFalse(alreadyIndexed(queries, monitor(), metadata()))
    }

    fun `test a monitor that follows the write index indexes its queries again after a rollover`() {
        val rolledOver = clusterState(writeIndex = "$alias-000002")
        val (queries, _) = queries(rolledOver, docsFound = 1)
        record(queries, monitor(deleteQueryIndexInEveryRun = true), clusterState())

        assertFalse(alreadyIndexed(queries, monitor(deleteQueryIndexInEveryRun = true), metadata(), rolledOver))
    }

    fun `test doIndexAllQueries returns the documents it wrote and their query index`() {
        val second = DocLevelQuery("q2", "q2", emptyList(), "user.name:\"root\"", emptyList(), listOf("user.name"))

        val written = indexAllQueries(listOf(query, second), failId = null)

        assertEquals(IndexedQueryDocs("q-uuid", setOf("q1_logs_mid", "q2_logs_mid")), written)
    }

    fun `test doIndexAllQueries returns nothing when a query was not indexed`() {
        val second = DocLevelQuery("q2", "q2", emptyList(), "user.name:\"root\"", emptyList(), listOf("user.name"))

        assertNull(indexAllQueries(listOf(query, second), failId = "q2_logs_mid"))
    }

    private fun monitor(
        vararg queries: DocLevelQuery = arrayOf(query),
        dataSources: DataSources = DataSources(),
        deleteQueryIndexInEveryRun: Boolean = false
    ): Monitor = randomDocumentLevelMonitor(
        inputs = listOf(DocLevelMonitorInput("description", listOf(source), queries.toList())),
        dataSources = dataSources
    ).copy(id = "mid", deleteQueryIndexInEveryRun = deleteQueryIndexInEveryRun)

    private fun metadata(mapped: Boolean = true) = MonitorMetadata(
        id = "mid-metadata",
        monitorId = "mid",
        lastActionExecutionTimes = emptyList(),
        lastRunContext = emptyMap(),
        sourceToQueryIndexMapping = if (mapped) mutableMapOf("${source}mid" to queryIndex) else mutableMapOf()
    )

    private fun clusterState(
        mappingVersion: Long = 1,
        settingsVersion: Long = 1,
        sourceUuid: String = "s-uuid",
        queryIndexUuid: String = "q-uuid",
        writeIndex: String = queryIndex
    ): ClusterState {
        fun index(name: String, uuid: String) = IndexMetadata.builder(name).settings(
            Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_INDEX_UUID, uuid)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
        )
        val metadata = Metadata.builder()
            .put(index(source, sourceUuid).mappingVersion(mappingVersion).settingsVersion(settingsVersion))
            .put(index(queryIndex, queryIndexUuid).putAlias(AliasMetadata.builder(alias).writeIndex(writeIndex == queryIndex)))
        if (writeIndex != queryIndex) {
            metadata.put(index(writeIndex, "q-next").putAlias(AliasMetadata.builder(alias).writeIndex(true)))
        }
        return ClusterState.builder(ClusterName("test")).metadata(metadata).build()
    }

    /**
     * A DocLevelMonitorQueries whose cluster state is [state] and whose query index holds [docsFound] of the
     * documents searched; the search fails when it is null.
     */
    private fun queries(state: ClusterState, docsFound: Long?): Pair<DocLevelMonitorQueries, Client> {
        val clusterService = mock(ClusterService::class.java)
        `when`(clusterService.state()).thenReturn(state)
        val client = mock(Client::class.java)
        doAnswer { invocation ->
            val listener = invocation.getArgument<ActionListener<SearchResponse>>(1)
            if (docsFound == null) listener.onFailure(IllegalStateException("search rejected")) else listener.onResponse(searchResponse(docsFound))
            null
        }.`when`(client).search(any(SearchRequest::class.java), any())
        return DocLevelMonitorQueries(client, clusterService) to client
    }

    private fun record(queries: DocLevelMonitorQueries, monitor: Monitor, state: ClusterState) {
        val indexed = IndexedQueries(IndexedQueriesState.of(monitor, listOf(source), queryIndex, "q-uuid", state), docIds)
        queries.indexedQueries.put("mid", source, indexed)
    }

    private fun alreadyIndexed(
        queries: DocLevelMonitorQueries,
        monitor: Monitor,
        metadata: MonitorMetadata,
        state: ClusterState = clusterState()
    ) = runBlocking { queries.queriesAlreadyIndexed(monitor, "mid", metadata, source, listOf(source), state) }

    private fun searchResponse(total: Long) = SearchResponse(
        InternalSearchResponse(
            SearchHits(arrayOf(), TotalHits(total, TotalHits.Relation.EQUAL_TO), 0f), null, null, null, false, false, 1
        ),
        null, 1, 1, 0, 1L, ShardSearchFailure.EMPTY_ARRAY, SearchResponse.Clusters.EMPTY
    )

    /** Runs doIndexAllQueries over source index `logs` and monitor `mid`, the bulk item [failId] failing. */
    private fun indexAllQueries(queries: List<DocLevelQuery>, failId: String?): IndexedQueryDocs? {
        val client = mock(Client::class.java)
        doAnswer { invocation ->
            val request = invocation.getArgument<BulkRequest>(0)
            val items = request.requests().mapIndexed { i, item ->
                if (item.id() == failId) {
                    BulkItemResponse(
                        i, DocWriteRequest.OpType.INDEX,
                        BulkItemResponse.Failure(queryIndex, item.id(), IllegalArgumentException("No field mapping can be found"))
                    )
                } else {
                    BulkItemResponse(
                        i, DocWriteRequest.OpType.INDEX,
                        IndexResponse(ShardId(Index(queryIndex, "q-uuid"), 0), item.id(), 1, 1, 1, true)
                    )
                }
            }
            invocation.getArgument<ActionListener<BulkResponse>>(1).onResponse(BulkResponse(items.toTypedArray(), 0))
            null
        }.`when`(client).bulk(any(), any())

        return runBlocking {
            DocLevelMonitorQueries(client, mock(ClusterService::class.java)).doIndexAllQueries(
                alias, source, "mid", queries, mutableSetOf(), emptySet(), RefreshPolicy.NONE, TimeValue.timeValueSeconds(1)
            )
        }
    }
}
