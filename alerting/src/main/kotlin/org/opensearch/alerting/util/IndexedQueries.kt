/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.opensearch.cluster.ClusterState
import org.opensearch.commons.alerting.model.DataSources
import org.opensearch.commons.alerting.model.Monitor
import java.util.concurrent.ConcurrentHashMap

/**
 * What the percolate queries of one source index of a doc-level monitor were built from.
 *
 * The queries depend on the monitor's queries, on the mappings of the concrete source indices (fields
 * are renamed, or pointed at [DocLevelMonitorQueries.ABSENT_FIELD_SENTINEL] when unmapped) and on the
 * query index they are stored in. While none of these change, indexing them again gives the same
 * documents.
 */
internal data class IndexedQueriesState(
    /** The indices and queries of the monitor, see [queryInputs]. */
    val queryInputs: List<Any>,
    val dataSources: DataSources,
    val deleteQueryIndexInEveryRun: Boolean?,
    /** The concrete source indices behind the source index, in resolution order. */
    val sourceIndices: List<SourceIndexVersion>,
    /** The query index the monitor metadata maps the source index to. */
    val queryIndex: String,
    /** The UUID of the concrete index the queries were written to, so that a recreated query index differs. */
    val queryIndexUuid: String
) {
    companion object {
        /** The state of [monitor]'s queries for [concreteIndices], as [clusterState] describes the source indices. */
        fun of(
            monitor: Monitor,
            concreteIndices: List<String>,
            queryIndex: String,
            queryIndexUuid: String,
            clusterState: ClusterState
        ) = IndexedQueriesState(
            monitor.queryInputs(),
            monitor.dataSources,
            monitor.deleteQueryIndexInEveryRun,
            concreteIndices.map { SourceIndexVersion.of(it, clusterState) },
            queryIndex,
            queryIndexUuid
        )
    }
}

/** A concrete source index, identified by its UUID, and the versions of its mapping and settings. */
internal data class SourceIndexVersion(val name: String, val uuid: String?, val mappingVersion: Long, val settingsVersion: Long) {
    companion object {
        fun of(name: String, clusterState: ClusterState): SourceIndexVersion {
            val metadata = clusterState.metadata.index(name)
            return SourceIndexVersion(name, metadata?.indexUUID, metadata?.mappingVersion ?: -1L, metadata?.settingsVersion ?: -1L)
        }
    }
}

/** The query documents a bulk request wrote, all of them in the concrete query index [queryIndexUuid]. */
internal data class IndexedQueryDocs(val queryIndexUuid: String, val docIds: Set<String>)

/** Queries indexed by a scheduled run: what they were built from, and the documents that hold them. */
internal data class IndexedQueries(val state: IndexedQueriesState, val docIds: Set<String>)

/**
 * The queries this node indexed on scheduled runs of its doc-level monitors, by monitor id and source index.
 *
 * Kept in memory only, so the first run after a node starts, or after a monitor moves to another node,
 * indexes its queries again.
 */
internal class IndexedQueriesRegistry {
    private val indexed = ConcurrentHashMap<Pair<String, String>, IndexedQueries>()

    fun get(monitorId: String, sourceIndex: String): IndexedQueries? = indexed[monitorId to sourceIndex]

    fun put(monitorId: String, sourceIndex: String, queries: IndexedQueries) {
        indexed[monitorId to sourceIndex] = queries
    }

    fun remove(monitorId: String, sourceIndex: String) {
        indexed.remove(monitorId to sourceIndex)
    }

    /** Forgets every source index of [monitorId]. */
    fun forget(monitorId: String) {
        indexed.keys.removeIf { it.first == monitorId }
    }
}
