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
