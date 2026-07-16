/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.core.lock

import org.junit.Assert.assertFalse
import org.mockito.Mockito.mock
import org.opensearch.cluster.service.ClusterService
import org.opensearch.core.action.ActionListener
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
}
