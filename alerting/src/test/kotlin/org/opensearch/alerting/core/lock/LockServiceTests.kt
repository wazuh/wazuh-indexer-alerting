/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.core.lock

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.opensearch.action.NoShardAvailableActionException
import org.opensearch.action.get.GetResponse
import org.opensearch.cluster.ClusterState
import org.opensearch.cluster.routing.IndexRoutingTable
import org.opensearch.cluster.routing.RoutingTable
import org.opensearch.cluster.service.ClusterService
import org.opensearch.core.action.ActionListener
import org.opensearch.core.index.shard.ShardId
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.client.Client

class LockServiceTests : OpenSearchTestCase() {
    fun `test release null is a no-op`() {
        val lockService = LockService(
            mock(Client::class.java),
            mock(ClusterService::class.java)
        )
        var released = true

        lockService.release(
            null,
            object : ActionListener<Boolean> {
                override fun onResponse(response: Boolean) {
                    released = response
                }

                override fun onFailure(e: Exception) {
                    fail("Unexpected failure: ${e.message}")
                }
            }
        )

        assertFalse(released)
    }

    fun `test findLock propagates a retriable failure without throwing`() {
        val client = mock(Client::class.java)
        val lockService = LockService(client, mock(ClusterService::class.java))
        val shardId = ShardId(LockService.LOCK_INDEX_NAME, "_na_", 0)
        val exception = NoShardAvailableActionException(shardId)

        doAnswer { invocation ->
            val listener = invocation.getArgument<ActionListener<GetResponse>>(1)
            listener.onFailure(exception)
            null
        }.`when`(client).get(any(), any())

        var responded = false
        var failure: Exception? = null
        lockService.findLock(
            "some-lock-id",
            object : ActionListener<LockModel> {
                override fun onResponse(response: LockModel?) {
                    responded = true
                }

                override fun onFailure(e: Exception) {
                    failure = e
                }
            }
        )

        assertFalse(responded)
        assertEquals(exception, failure)
    }

    /**
     * The lock index enters the routing table well before its shard can serve reads (8.5s on a node
     * recovering 108 indices). Acquiring must report "no lock" instead of issuing a get that is bound to
     * fail with NoShardAvailableActionException.
     */
    fun `test acquireLock skips the run while the lock index primary is inactive`() {
        val client = mock(Client::class.java)
        val lockService = LockService(client, clusterServiceWithLockIndex(primaryActive = false))

        var responded = false
        var lock: LockModel? = LockModel("some-job-id", java.time.Instant.now(), false)
        lockService.acquireLockWithId(
            "some-job-id",
            object : ActionListener<LockModel?> {
                override fun onResponse(response: LockModel?) {
                    responded = true
                    lock = response
                }

                override fun onFailure(e: Exception) {
                    fail("Unexpected failure: ${e.message}")
                }
            }
        )

        assertTrue(responded)
        assertNull(lock)
        // No request may be issued against a shard that cannot answer.
        verify(client, never()).get(any(), any())
    }

    private fun clusterServiceWithLockIndex(primaryActive: Boolean): ClusterService {
        val clusterService = mock(ClusterService::class.java)
        val clusterState = mock(ClusterState::class.java)
        val routingTable = mock(RoutingTable::class.java)
        val indexRoutingTable = mock(IndexRoutingTable::class.java)

        `when`(clusterService.state()).thenReturn(clusterState)
        `when`(clusterState.routingTable()).thenReturn(routingTable)
        `when`(routingTable.hasIndex(LockService.LOCK_INDEX_NAME)).thenReturn(true)
        `when`(routingTable.index(LockService.LOCK_INDEX_NAME)).thenReturn(indexRoutingTable)
        `when`(indexRoutingTable.allPrimaryShardsActive()).thenReturn(primaryActive)

        return clusterService
    }
}
