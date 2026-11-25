/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.alerting

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.apache.lucene.search.TotalHits
import org.opensearch.alerting.util.isActiveResponseMonitor
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.core.index.Index
import org.opensearch.core.index.shard.ShardId
import org.opensearch.index.query.BoolQueryBuilder
import org.opensearch.index.query.QueryBuilder
import org.opensearch.index.query.QueryBuilders
import org.opensearch.index.search.QueryParserHelper
import org.opensearch.index.seqno.SequenceNumbers
import org.opensearch.search.SearchHits
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.cancellation.CancellationException
import kotlin.math.max
import kotlin.math.min

private val logger: Logger = LogManager.getLogger("FanOutEligibility")

private const val ALL_FIELDS = "*"

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
 * Records that a shard has been read up to [maxSeqNo] when the documents left in that range need no
 * evaluation, which is the case of a read narrowed by [matchFilterOf].
 *
 * With nothing waiting in the batch the sequence number is committed at once, and the one held back for the
 * shard is dropped so that a later batch cannot commit a lower one over it. Otherwise it is held back like
 * any other, and committed when the documents already read from the shard have been evaluated.
 */
fun markShardRead(
    shard: String,
    maxSeqNo: Long,
    batchIsEmpty: Boolean,
    pendingSeqNos: MutableMap<String, Long>,
    commitSeqNo: (String, Long) -> Unit
) {
    if (batchIsEmpty) {
        pendingSeqNos.remove(shard)
        commitSeqNo(shard, maxSeqNo)
    } else {
        pendingSeqNos[shard] = maxSeqNo
    }
}

/**
 * Gives the filter that narrows the shard read of an Active Response monitor to the documents that match
 * at least one of its queries, or null for any other monitor.
 *
 * A doc-level monitor reads every new document of its indices and percolates it against its queries. An
 * Active Response monitor reads the findings data streams, where nearly every document matches none of its
 * few queries, so that read is large for nothing: search backpressure cancels it on a node under pressure
 * and the responses are late. Its queries are `query_string` queries written for the source index, so the
 * index can apply them itself and return only the documents worth percolating.
 *
 * The clauses are built the way the queries are stored for percolation. Other doc-level monitors, such as
 * the ones behind threat detectors, can carry thousands of queries and keep the full read.
 */
fun matchFilterOf(monitor: Monitor): QueryBuilder? {
    if (!monitor.isActiveResponseMonitor()) return null
    val queries = (monitor.inputs.firstOrNull() as? DocLevelMonitorInput)?.queries.orEmpty()
    if (queries.isEmpty()) return null
    val anyQuery = BoolQueryBuilder().minimumShouldMatch(1)
    queries.forEach { query ->
        val fields = query.fields.ifEmpty { listOf(ALL_FIELDS) }
        anyQuery.should(
            QueryBuilders.queryStringQuery(query.query).fields(QueryParserHelper.parseFieldsAndWeights(fields))
        )
    }
    return anyQuery
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

/**
 * The smallest batch [DocLevelBatchLimits] halves a monitor down to. A percolate search has a fixed cost, tens of
 * megabytes for a monitor with many queries, whatever the number of documents, so a smaller batch would not make
 * it much lighter.
 */
const val MIN_HALVED_BATCH_SIZE = 1000

/** How long a halved monitor must run without a refused search before [DocLevelBatchLimits] doubles its batches. */
val HALVED_BATCH_RECOVERY: Duration = Duration.ofMinutes(15)

/**
 * Batch limits, on this node, of the doc-level monitors whose shard reads or percolate searches the node refused for
 * want of memory.
 *
 * A refused batch is deferred, and the next run reads the same documents again. At the same size it is refused again
 * for as long as the node stays under pressure, and the monitor falls behind. So a refusal
 * halves the monitor's batches instead, down to [minBatchSize]: the next run evaluates the same documents in smaller
 * searches. After [recovery] without another refusal the limit doubles, and once it is back to the configured sizes
 * the monitor is forgotten.
 *
 * Only the monitors that were refused are tracked, so every other monitor keeps the configured sizes. The limits are
 * kept in memory, so a restarted node starts again from the configured sizes.
 */
class DocLevelBatchLimits(
    private val recovery: Duration = HALVED_BATCH_RECOVERY,
    private val minBatchSize: Int = MIN_HALVED_BATCH_SIZE,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {
    private data class Limit(val size: Int, val since: Long)

    private val limits = ConcurrentHashMap<String, Limit>()

    /** How many monitors run with halved batches. */
    val halvedMonitors: Int
        get() = limits.size

    /**
     * Returns the size [monitorId] may use for a batch whose configured size is [configured]: a shard read or a
     * percolate search. [largestConfigured] is the larger of the two configured sizes, the point where a halved limit
     * has doubled back and the monitor is forgotten.
     */
    fun sizeFor(monitorId: String, configured: Int, largestConfigured: Int): Int {
        val limit = limits.computeIfPresent(monitorId) { _, limit -> recovered(monitorId, limit, largestConfigured) }
        return if (limit == null) configured else min(configured, limit.size)
    }

    /**
     * Halves the batches of [monitorId] after the node refused one of [refusedSize] documents, and returns the new
     * limit. A refusal never raises a limit that is already lower, and it restarts the wait for the next doubling.
     */
    fun halve(monitorId: String, refusedSize: Int): Int {
        val halved = max(minBatchSize, refusedSize / 2)
        return limits.compute(monitorId) { _, limit -> Limit(min(halved, limit?.size ?: halved), nowMillis()) }!!.size
    }

    private fun recovered(monitorId: String, limit: Limit, largestConfigured: Int): Limit? {
        val now = nowMillis()
        val periods = (now - limit.since) / recovery.toMillis()
        if (periods <= 0) {
            return limit
        }
        val size = limit.size.toLong() shl periods.coerceAtMost(31).toInt()
        if (size >= largestConfigured) {
            log.info(
                "Monitor $monitorId: no search refused for ${recovery.toMinutes()} minutes on this node, so it is " +
                    "back to the configured batch sizes."
            )
            return null
        }
        log.info(
            "Monitor $monitorId: no search refused for ${recovery.toMinutes()} minutes on this node, so its shard " +
                "reads and percolate searches now take at most $size documents."
        )
        return Limit(size.toInt(), now)
    }

    private companion object {
        val log: Logger = LogManager.getLogger(DocLevelBatchLimits::class.java)
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
