/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.alerting.workflow

import org.opensearch.OpenSearchException
import org.opensearch.Version
import org.opensearch.cluster.node.DiscoveryNode
import org.opensearch.node.NodeClosedException
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.NodeNotConnectedException
import org.opensearch.transport.RemoteTransportException
import java.io.IOException

class CompositeWorkflowRunnerTests : OpenSearchTestCase() {

    private fun node() = DiscoveryNode("node", buildNewFakeTransportAddress(), Version.CURRENT)

    fun `test node closed exception is a node unavailable failure`() {
        assertTrue(isNodeUnavailableFailure(NodeClosedException(node())))
    }

    fun `test node not connected exception is a node unavailable failure`() {
        assertTrue(isNodeUnavailableFailure(NodeNotConnectedException(node(), "not connected")))
    }

    fun `test wrapped node closed exception is a node unavailable failure`() {
        // A shutdown seen through a transport hop arrives wrapped; the cause must still be recognised.
        val wrapped = RemoteTransportException("indices:admin/create", NodeClosedException(node()))
        assertTrue(isNodeUnavailableFailure(wrapped))
    }

    fun `test genuine failure is not a node unavailable failure`() {
        // An alert index that cannot be read is a real error and must keep error-level logging.
        assertFalse(isNodeUnavailableFailure(OpenSearchException("all shards failed")))
        assertFalse(isNodeUnavailableFailure(IllegalStateException("boom")))
        assertFalse(isNodeUnavailableFailure(IOException("disk gone")))
    }

    fun `test wrapped genuine failure is not a node unavailable failure`() {
        val wrapped = RemoteTransportException("indices:data/read/search", IllegalStateException("boom"))
        assertFalse(isNodeUnavailableFailure(wrapped))
    }
}
