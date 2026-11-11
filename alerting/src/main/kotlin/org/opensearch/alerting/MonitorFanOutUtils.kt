/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.alerting

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.apache.lucene.search.TotalHits
import org.opensearch.core.index.Index
import org.opensearch.core.index.shard.ShardId
import org.opensearch.index.seqno.SequenceNumbers
import org.opensearch.search.SearchHits
import kotlin.coroutines.cancellation.CancellationException

private val logger: Logger = LogManager.getLogger("FanOutEligibility")

/**
 * Commits every shard sequence number held back in [pendingSeqNos], then clears them.
 *
 * A doc-level monitor reads a shard in chunks but evaluates them a whole batch at a time, so a chunk's
 * sequence number must not be recorded as covered until the percolate search for the batch holding it has
 * succeeded. Advancing it on fetch instead is what let a refused search skip documents for good: the batch
 * was discarded while the shard had already been moved past it.
 *
 * Call this only when the batch was evaluated. Leaving the entries pending is what makes the next run read
 * those documents again.
 */
fun commitPendingSeqNos(pendingSeqNos: MutableMap<String, Long>, commitSeqNo: (String, Long) -> Unit) {
    pendingSeqNos.forEach { (shard, seqNo) -> commitSeqNo(shard, seqNo) }
    pendingSeqNos.clear()
}

/**
 * Describes how a doc-level monitor's percolate search fell short of returning every query it matched, or
 * returns null when it returned all of them.
 *
 * Each hit of that search is a stored query that matched at least one document of the batch, and the search
 * returns no more hits than its `size`. A match past that cap produces no finding, so the caller logs the
 * shortfall instead of letting it go unnoticed. The total is exact up to the default `track_total_hits`
 * threshold (10,000); past it the total is only a lower bound, which still means more matches than were
 * returned.
 */
fun describePercolateTruncation(hits: SearchHits): String? {
    val total = hits.totalHits ?: return null
    val returned = hits.hits.size
    return when {
        total.relation == TotalHits.Relation.GREATER_THAN_OR_EQUAL_TO -> "matched more than the $returned queries it returned"
        total.value > returned -> "matched ${total.value} queries but returned only $returned"
        else -> null
    }
}

/**
 * How many failing documents [percolateIsolatingFailures] looks for in one batch. A failure that hits more
 * documents than this is unlikely to come from a few values, so the search for them stops there to keep the
 * cost of a bad batch bounded.
 */
const val MAX_ISOLATED_PERCOLATE_FAILURES = 10

/**
 * The outcome of [percolateIsolatingFailures]: [failing] holds the documents that fail on their own, and
 * [unresolved] the ones left unevaluated once [MAX_ISOLATED_PERCOLATE_FAILURES] was reached. Every other
 * document was evaluated.
 */
data class PercolateIsolation<T>(val failing: List<T>, val unresolved: List<T>)

/**
 * Evaluates [docs] in parts after the percolate search over all of them failed for a reason that is not
 * transient, so that a document the query index cannot hold costs only itself instead of its whole batch.
 *
 * A failing part is split in halves, and each half is percolated on its own, until the failure is narrowed
 * down to single documents. One failing document among `n` costs about `2 * log2(n)` searches, and every other
 * document is evaluated exactly once. Once [maxFailing] documents have been isolated, a part that fails is
 * given up whole instead of split again.
 *
 * [percolate] evaluates one part and throws when it fails. A failure that [isTransient] accepts is not a
 * property of the documents, so it is rethrown: the caller defers the whole batch, as it does when the first
 * search is refused.
 *
 * @param docs the batch, already known to fail as a whole.
 */
suspend fun <T> percolateIsolatingFailures(
    docs: List<T>,
    maxFailing: Int,
    isTransient: (Exception) -> Boolean,
    percolate: suspend (List<T>) -> Unit,
): PercolateIsolation<T> {
    val failing = mutableListOf<T>()
    val unresolved = mutableListOf<T>()

    suspend fun narrowDown(part: List<T>) {
        if (part.size == 1) {
            failing += part
            return
        }
        if (failing.size >= maxFailing) {
            unresolved += part
            return
        }
        val middle = part.size / 2
        for (half in listOf(part.subList(0, middle), part.subList(middle, part.size))) {
            try {
                percolate(half)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (isTransient(e)) throw e
                narrowDown(half)
            }
        }
    }

    narrowDown(docs)
    return PercolateIsolation(failing, unresolved)
}

fun distributeShards(
    maxFanoutNodes: Int,
    allNodes: List<String>,
    shards: List<String>,
    index: Index,
): Map<String, MutableSet<ShardId>> {
    val totalShards = shards.size
    val numFanOutNodes = allNodes.size.coerceAtMost(totalShards)
    val totalNodes = maxFanoutNodes.coerceAtMost(numFanOutNodes)

    val shardIdList = shards.map {
        ShardId(index, it.toInt())
    }
    val shuffledNodes = allNodes.shuffled()
    val nodes = shuffledNodes.subList(0, totalNodes)

    val nodeShardAssignments = nodes.associateWith { mutableSetOf<ShardId>() }

    if (nodeShardAssignments.isEmpty()) {
        logger.error("No nodes eligible for fanout")
        return nodeShardAssignments
    }

    shardIdList.forEachIndexed { idx, shardId ->
        val nodeIdx = idx % nodes.size
        val node = nodes[nodeIdx]
        nodeShardAssignments[node]!!.add(shardId)
    }

    return nodeShardAssignments
}

/**
 * Initializes the last run context for a given index.
 *
 * This method prepares the context structure to be updated later by fan-out operations.
 * It preserves existing sequence numbers and initializes new shards with UNASSIGNED_SEQ_NO.
 *
 * @param lastRunContext The previous run context from monitor metadata
 * @param monitorCtx The execution context containing cluster service
 * @param index The name of the index for which the context is being initialized
 * @return A map containing the initialized last run context
 */
fun initializeNewLastRunContext(
    lastRunContext: Map<String, Any>,
    index: String,
    shardCount: Int,
): Map<String, Any> {
    val updatedLastRunContext = lastRunContext.toMutableMap()

    // Only initialize shards that don't already have a sequence number
    for (i: Int in 0 until shardCount) {
        val shard = i.toString()
        // Preserve existing sequence numbers instead of resetting to UNASSIGNED
        if (!updatedLastRunContext.containsKey(shard)) {
            updatedLastRunContext[shard] = SequenceNumbers.UNASSIGNED_SEQ_NO
        }
    }

    // Metadata fields
    updatedLastRunContext["shards_count"] = shardCount
    updatedLastRunContext["index"] = index

    return updatedLastRunContext
}
