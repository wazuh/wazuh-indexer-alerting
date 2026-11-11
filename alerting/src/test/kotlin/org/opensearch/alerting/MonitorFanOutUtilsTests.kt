/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.alerting

import kotlinx.coroutines.runBlocking
import org.apache.lucene.search.TotalHits
import org.apache.lucene.search.TotalHits.Relation
import org.opensearch.core.index.Index
import org.opensearch.core.index.shard.ShardId
import org.opensearch.search.SearchHit
import org.opensearch.search.SearchHits
import org.opensearch.test.OpenSearchTestCase

class MonitorFanOutUtilsTests : OpenSearchTestCase() {
    fun `test distribute few shards many nodes`() {
        val result = distributeShards(
            1000,
            listOf("nodeA", "nodeB", "nodeC", "nodeD", "nodeE"),
            listOf("0", "1"),
            Index("index1", "id1")
        )

        validateDistribution(result, 2, listOf(1), 2)
    }

    fun `test distribute randomizes the assigned node`() {
        val nodes = mutableSetOf<String>()

        // Picking a node to distribute to is random. To reduce test flakiness, we run this 100 times to give a (1/5)^99 chance
        // that the same node is picked every time
        repeat(100) {
            val result = distributeShards(
                1000,
                listOf("nodeA", "nodeB", "nodeC", "nodeD", "nodeE"),
                listOf("0"),
                Index("index1", "id1")
            )

            validateDistribution(result, 1, listOf(1), 1)
            nodes.addAll(result.keys)
        }

        assertTrue(nodes.size > 1)
    }

    fun `test distribute many shards few nodes`() {
        val result = distributeShards(
            1000,
            listOf("nodeA", "nodeB", "nodeC"),
            listOf("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
            Index("index1", "id1")
        )

        validateDistribution(result, 3, listOf(3, 4), 10)
    }

    fun `test distribute max nodes limits`() {
        val result = distributeShards(
            2,
            listOf("nodeA", "nodeB", "nodeC"),
            listOf("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
            Index("index1", "id1")
        )

        validateDistribution(result, 2, listOf(5), 10)
    }

    fun `test distribute edge case 1 shard`() {
        val result = distributeShards(
            1000,
            listOf("nodeA", "nodeB", "nodeC"),
            listOf("0"),
            Index("index1", "id1")
        )

        validateDistribution(result, 1, listOf(1), 1)
    }

    fun `test distribute edge case 1 node`() {
        val result = distributeShards(
            1000,
            listOf("nodeA"),
            listOf("0", "1", "2"),
            Index("index1", "id1")
        )

        validateDistribution(result, 1, listOf(3), 3)
    }

    fun `test distribute edge case 1 shard 1 node`() {
        val result = distributeShards(
            1000,
            listOf("nodeA"),
            listOf("0"),
            Index("index1", "id1")
        )

        validateDistribution(result, 1, listOf(1), 1)
    }

    fun `test distribute edge case no nodes does not throw`() {
        val result = distributeShards(
            1000,
            listOf(),
            listOf("0"),
            Index("index1", "id1")
        )

        validateDistribution(result, 0, listOf(), 0)
    }

    fun `test distribute edge case no shards does not throw`() {
        val result = distributeShards(
            1000,
            listOf("nodeA"),
            listOf(),
            Index("index1", "id1")
        )

        validateDistribution(result, 0, listOf(), 0)
    }

    private fun validateDistribution(
        result: Map<String, MutableSet<ShardId>>,
        expectedNodeCount: Int,
        expectedShardsPerNode: List<Int>,
        expectedTotalShardCount: Int
    ) {
        assertEquals(expectedNodeCount, result.keys.size)
        var shardCount = 0
        result.forEach { (_, shards) ->
            assertTrue(expectedShardsPerNode.contains(shards.size))
            shardCount += shards.size
        }
        assertEquals(expectedTotalShardCount, shardCount)
    }

    fun `test evaluating a batch commits every held-back sequence number`() {
        // Five 10000-document chunks were read from shard 0 before the batch was percolated.
        val pending = mutableMapOf("0" to 49999L)
        val committed = mutableMapOf<String, Long>()

        commitPendingSeqNos(pending) { shard, seqNo -> committed[shard] = seqNo }

        assertEquals(mapOf("0" to 49999L), committed)
        assertTrue("Committed sequence numbers must not be committed twice", pending.isEmpty())
    }

    fun `test every shard read into the batch is committed`() {
        // One batch can span several shards of an index; all of them are covered by the same search.
        val pending = mutableMapOf("0" to 9999L, "1" to 4999L, "2" to 7999L)
        val committed = mutableMapOf<String, Long>()

        commitPendingSeqNos(pending) { shard, seqNo -> committed[shard] = seqNo }

        assertEquals(mapOf("0" to 9999L, "1" to 4999L, "2" to 7999L), committed)
        assertTrue(pending.isEmpty())
    }

    fun `test committing an empty batch does nothing`() {
        val pending = mutableMapOf<String, Long>()
        commitPendingSeqNos(pending) { _, _ -> fail("there was nothing to commit") }
        assertTrue(pending.isEmpty())
    }

    fun `test a percolate search that returned every matched query is not reported`() {
        assertNull(describePercolateTruncation(percolateHits(returned = 12, total = 12, Relation.EQUAL_TO)))
    }

    fun `test a percolate search with no match is not reported`() {
        assertNull(describePercolateTruncation(percolateHits(returned = 0, total = 0, Relation.EQUAL_TO)))
    }

    fun `test a percolate search capped below its exact total is reported with both counts`() {
        // 15 queries matched, but the search was sized for 10: five matches would produce no finding.
        assertEquals(
            "matched 15 queries but returned only 10",
            describePercolateTruncation(percolateHits(returned = 10, total = 15, Relation.EQUAL_TO))
        )
    }

    fun `test a percolate search whose total is only a lower bound is reported`() {
        // Past the track_total_hits threshold the total stops counting, so it can equal the number returned.
        assertEquals(
            "matched more than the 10 queries it returned",
            describePercolateTruncation(percolateHits(returned = 10, total = 10, Relation.GREATER_THAN_OR_EQUAL_TO))
        )
    }

    fun `test a percolate search without a total is not reported`() {
        val hits = SearchHits(Array(10) { SearchHit(it) }, null, 1.0f)
        assertNull(describePercolateTruncation(hits))
    }

    private fun percolateHits(returned: Int, total: Long, relation: Relation): SearchHits =
        SearchHits(Array(returned) { SearchHit(it) }, TotalHits(total, relation), 1.0f)

    fun `test one failing document costs only itself and a few searches`() {
        val percolator = FakePercolator(failing = setOf(4321))

        val isolation = isolate((0 until 50000).toList(), percolator)

        assertEquals(listOf(4321), isolation.failing)
        assertTrue(isolation.unresolved.isEmpty())
        assertEquals("every other document is evaluated exactly once", (0 until 50000).toSet() - 4321, percolator.evaluatedOnce())
        // Two searches per halving: the batch is split 16 times on the way down to the failing document.
        assertTrue("took ${percolator.searches} searches", percolator.searches <= 2 * 16)
    }

    fun `test several failing documents are each isolated`() {
        val percolator = FakePercolator(failing = setOf(0, 517, 518, 999))

        val isolation = isolate((0 until 1000).toList(), percolator)

        assertEquals(listOf(0, 517, 518, 999), isolation.failing)
        assertTrue(isolation.unresolved.isEmpty())
        assertEquals((0 until 1000).toSet() - setOf(0, 517, 518, 999), percolator.evaluatedOnce())
    }

    fun `test a failure that hits every document stops after the cap`() {
        // Not a few bad values but a defect of the search itself: it must not cost a search per document.
        val percolator = FakePercolator(failing = (0 until 50000).toSet())

        val isolation = isolate((0 until 50000).toList(), percolator)

        assertTrue(isolation.failing.size <= MAX_ISOLATED_PERCOLATE_FAILURES + 1)
        assertEquals((0 until 50000).toList(), (isolation.failing + isolation.unresolved).sorted())
        assertTrue("took ${percolator.searches} searches", percolator.searches <= 100)
    }

    fun `test a batch of one failing document needs no further search`() {
        val percolator = FakePercolator(failing = setOf(7))

        val isolation = isolate(listOf(7), percolator)

        assertEquals(listOf(7), isolation.failing)
        assertEquals(0, percolator.searches)
    }

    fun `test a failure no part reproduces leaves nothing out`() {
        // The batch failed as a whole, but every half succeeds on its own.
        val percolator = FakePercolator(failing = emptySet())

        val isolation = isolate((0 until 100).toList(), percolator)

        assertTrue(isolation.failing.isEmpty())
        assertTrue(isolation.unresolved.isEmpty())
        assertEquals((0 until 100).toSet(), percolator.evaluatedOnce())
    }

    fun `test a part refused for lack of resources is rethrown so the batch is deferred`() {
        val percolator = FakePercolator(failing = setOf(10), transientAfter = 3)

        expectThrows(IllegalStateException::class.java) { isolate((0 until 100).toList(), percolator) }
    }

    private fun isolate(docs: List<Int>, percolator: FakePercolator): PercolateIsolation<Int> = runBlocking {
        percolateIsolatingFailures(docs, MAX_ISOLATED_PERCOLATE_FAILURES, { it is IllegalStateException }) {
            percolator.percolate(it)
        }
    }

    /**
     * Fails any part holding a document of [failing], like a value the query index cannot hold, and every
     * search past [transientAfter] with an exception the test classifies as transient.
     */
    private class FakePercolator(val failing: Set<Int>, val transientAfter: Int = Int.MAX_VALUE) {
        var searches = 0
        private val evaluated = mutableListOf<Int>()

        fun percolate(part: List<Int>) {
            searches++
            if (searches > transientAfter) throw IllegalStateException("cancelled")
            if (part.any { it in failing }) throw IllegalArgumentException("immense term")
            evaluated += part
        }

        fun evaluatedOnce(): Set<Int> {
            assertEquals("a document was evaluated twice", evaluated.size, evaluated.toSet().size)
            return evaluated.toSet()
        }
    }
}
