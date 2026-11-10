/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.transport

import kotlinx.coroutines.runBlocking
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.mock
import org.opensearch.alerting.randomDocumentLevelMonitor
import org.opensearch.alerting.util.DocLevelMonitorQueries
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.document.DocumentField
import org.opensearch.common.unit.TimeValue
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.core.action.ActionListener
import org.opensearch.core.common.bytes.BytesArray
import org.opensearch.index.query.BoolQueryBuilder
import org.opensearch.index.query.IdsQueryBuilder
import org.opensearch.index.query.MatchQueryBuilder
import org.opensearch.index.reindex.BulkByScrollResponse
import org.opensearch.index.reindex.BulkByScrollTask
import org.opensearch.index.reindex.DeleteByQueryAction
import org.opensearch.index.reindex.DeleteByQueryRequest
import org.opensearch.search.SearchHit
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.client.Client

/** Query documents of queries a monitor no longer lists (wazuh/wazuh-indexer#2105). */
class UnlistedQueriesTests : OpenSearchTestCase() {

    private val listed = DocLevelQuery("listed", "listed", emptyList(), "user.name:\"admin\"", emptyList(), listOf("user.name"))
    private val monitor = randomDocumentLevelMonitor(
        inputs = listOf(DocLevelMonitorInput("description", listOf("logs"), listOf(listed)))
    ).copy(id = "mid")
    private val docs = listOf(
        "d1" to TransportDocLevelMonitorFanOutAction.TransformedDocDto("logs", "logs-000001", "d1", BytesArray("{}"))
    )

    fun `test percolate hits of queries the monitor does not list are left out of the run results`() {
        val inputRunResults = mutableMapOf<String, MutableSet<String>>()
        val docsToQueries = mutableMapOf<String, MutableList<String>>()

        val unlisted = collectPercolateHits(
            listOf(hit("listed_logs_mid"), hit("removed_logs_mid")),
            docs,
            monitor,
            listOf("logs-000001"),
            listOf("logs"),
            inputRunResults,
            docsToQueries
        )

        assertEquals(setOf("removed"), unlisted)
        assertEquals(mapOf("listed" to mutableSetOf("d1|logs-000001")), inputRunResults)
        assertEquals(mapOf("d1|logs-000001" to mutableListOf("listed")), docsToQueries)
    }

    fun `test the query documents of the monitor other than the current ones are deleted`() {
        val client = mock(Client::class.java)
        val requests = mutableListOf<DeleteByQueryRequest>()
        doAnswer { invocation ->
            requests.add(invocation.getArgument(1))
            invocation.getArgument<ActionListener<BulkByScrollResponse>>(2).onResponse(deleted(3))
            null
        }.`when`(client).execute(eq(DeleteByQueryAction.INSTANCE), any(DeleteByQueryRequest::class.java), any())

        runBlocking {
            DocLevelMonitorQueries(client, mock(ClusterService::class.java))
                .deleteUnlistedQueries("mid", setOf("queries-000001"), setOf("listed_logs_mid"))
        }

        val request = requests.single()
        assertEquals(listOf("queries-000001"), request.indices().toList())
        assertTrue("the deleted documents must not be found by the next percolate search", request.isRefresh)
        val query = request.searchRequest.source().query() as BoolQueryBuilder
        val monitorFilter = query.filter().filterIsInstance<BoolQueryBuilder>().flatMap { it.filter() } + query.filter()
        assertTrue(monitorFilter.any { it is MatchQueryBuilder && it.fieldName() == "monitor_id" && it.value() == "mid" })
        val kept = (query.mustNot().single() as IdsQueryBuilder).ids()
        assertEquals(setOf("listed_logs_mid"), kept)
    }

    fun `test a failure to delete them does not fail the run`() {
        val client = mock(Client::class.java)
        doAnswer { invocation ->
            invocation.getArgument<ActionListener<BulkByScrollResponse>>(2).onFailure(IllegalStateException("rejected"))
            null
        }.`when`(client).execute(eq(DeleteByQueryAction.INSTANCE), any(DeleteByQueryRequest::class.java), any())

        runBlocking {
            DocLevelMonitorQueries(client, mock(ClusterService::class.java))
                .deleteUnlistedQueries("mid", setOf("queries-000001"), setOf("listed_logs_mid"))
        }
    }

    private fun hit(id: String) = SearchHit(
        0, id, mapOf("_percolator_document_slot" to DocumentField("_percolator_document_slot", listOf<Any>(0))), emptyMap()
    )

    private fun deleted(n: Long) = BulkByScrollResponse(
        TimeValue.timeValueMillis(1),
        BulkByScrollTask.Status(null, n, 0, 0, n, 1, 0, 0, 0, 0, TimeValue.ZERO, 0f, null, TimeValue.ZERO),
        emptyList(),
        emptyList(),
        false
    )
}
