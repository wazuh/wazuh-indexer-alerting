/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.core.lock

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.mock
import org.opensearch.action.NoShardAvailableActionException
import org.opensearch.action.get.GetResponse
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
}
