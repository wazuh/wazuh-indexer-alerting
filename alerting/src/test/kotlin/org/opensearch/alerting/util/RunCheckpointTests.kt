/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.opensearch.alerting.randomDocLevelMonitorInput
import org.opensearch.alerting.randomDocLevelQuery
import org.opensearch.alerting.randomDocumentLevelMonitor
import org.opensearch.common.settings.Settings
import org.opensearch.commons.alerting.model.BucketLevelTrigger
import org.opensearch.commons.alerting.model.ChainedAlertTrigger
import org.opensearch.commons.alerting.model.DataSources
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocumentLevelTrigger
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.model.QueryLevelTrigger
import org.opensearch.commons.alerting.model.SearchInput
import org.opensearch.commons.alerting.model.Workflow
import org.opensearch.core.xcontent.NamedXContentRegistry
import org.opensearch.search.SearchModule
import org.opensearch.test.OpenSearchTestCase
import java.time.Instant
import java.time.temporal.ChronoUnit

/** Tests the doc-level query change check and the run checkpoint merge (wazuh/wazuh-indexer#1968). */
class RunCheckpointTests : OpenSearchTestCase() {

    override fun xContentRegistry(): NamedXContentRegistry {
        return NamedXContentRegistry(
            mutableListOf(
                Monitor.XCONTENT_REGISTRY,
                SearchInput.XCONTENT_REGISTRY,
                DocLevelMonitorInput.XCONTENT_REGISTRY,
                QueryLevelTrigger.XCONTENT_REGISTRY,
                BucketLevelTrigger.XCONTENT_REGISTRY,
                DocumentLevelTrigger.XCONTENT_REGISTRY,
                Workflow.XCONTENT_REGISTRY,
                ChainedAlertTrigger.XCONTENT_REGISTRY
            ) + SearchModule(Settings.EMPTY, emptyList()).namedXContents
        )
    }

    private fun docLevelMonitor(input: DocLevelMonitorInput = randomDocLevelMonitorInput(), queryIndex: String = "query-index"): Monitor =
        randomDocumentLevelMonitor(inputs = listOf(input), dataSources = DataSources(queryIndex = queryIndex))

    fun `test queries unchanged when only the schedule, triggers or enabled flag move`() {
        val monitor = docLevelMonitor()
        // A monitor's enabled time follows its enabled flag, so the two move together.
        val edited = monitor.copy(
            enabled = !monitor.enabled,
            enabledTime = if (monitor.enabled) null else Instant.now().truncatedTo(ChronoUnit.MILLIS),
            triggers = emptyList(),
            name = monitor.name + "-renamed"
        )
        assertFalse(docLevelQueriesChanged(monitor, edited))
    }

    fun `test queries changed when a query is edited`() {
        val input = randomDocLevelMonitorInput(queries = listOf(randomDocLevelQuery(id = "rule-1", query = "event.action:sudo")))
        val monitor = docLevelMonitor(input)
        val editedInput = input.copy(queries = listOf(randomDocLevelQuery(id = "rule-1", query = "event.action:su")))
        assertTrue(docLevelQueriesChanged(monitor, monitor.copy(inputs = listOf(editedInput))))
    }

    fun `test queries unchanged when only the input description or fan-out flag move`() {
        // Security Analytics sets the input description to the detector name, so this is a detector rename.
        val input = randomDocLevelMonitorInput()
        val monitor = docLevelMonitor(input)
        val renamed = monitor.copy(inputs = listOf(input.copy(description = input.description + "-renamed")))
        assertFalse(docLevelQueriesChanged(monitor, renamed))
        val fanOutToggled = monitor.copy(inputs = listOf(input.copy(fanoutEnabled = input.fanoutEnabled != true)))
        assertFalse(docLevelQueriesChanged(monitor, fanOutToggled))
    }

    fun `test queries changed when the input indices change`() {
        val input = randomDocLevelMonitorInput(indices = listOf("events-1"))
        val monitor = docLevelMonitor(input)
        assertTrue(docLevelQueriesChanged(monitor, monitor.copy(inputs = listOf(input.copy(indices = listOf("events-2"))))))
    }

    fun `test queries changed when the query index moves`() {
        val monitor = docLevelMonitor(queryIndex = "query-index")
        assertTrue(docLevelQueriesChanged(monitor, monitor.copy(dataSources = DataSources(queryIndex = "other-query-index"))))
    }

    fun `test stored form reads as unchanged against the monitor it came from`() {
        val monitor = docLevelMonitor()
        val stored = storedForm(monitor, xContentRegistry())
        assertFalse(docLevelQueriesChanged(monitor, stored))
        // Idempotent: storing it again changes nothing either.
        assertFalse(docLevelQueriesChanged(stored, storedForm(stored, xContentRegistry())))
    }

    fun `test merge keeps the higher sequence number per shard`() {
        val base = mapOf<String, Any>("events-1" to mapOf("index" to "events-1", "shards_count" to 2, "0" to 10L, "1" to 10L))
        val ours = mapOf<String, Any>("events-1" to mutableMapOf<String, Any>("index" to "events-1", "shards_count" to 2, "0" to 50L, "1" to 20L))
        val theirs = mapOf<String, Any>("events-1" to mapOf("index" to "events-1", "shards_count" to 2, "0" to 10L, "1" to 90L))

        val merged = mergeRunCheckpoints(base, ours, theirs)["events-1"] as Map<*, *>

        assertEquals(50L, merged["0"])
        assertEquals(90L, merged["1"])
        assertEquals("events-1", merged["index"])
        assertEquals(2, merged["shards_count"])
    }

    fun `test merge keeps an index only the other writer registered`() {
        val base = mapOf<String, Any>("events-1" to mapOf("0" to 10L))
        val ours = mapOf<String, Any>("events-1" to mutableMapOf<String, Any>("0" to 50L))
        val theirs = mapOf<String, Any>("events-1" to mapOf("0" to 10L), "events-2" to mapOf("0" to -1L))

        val merged = mergeRunCheckpoints(base, ours, theirs)

        assertEquals(mapOf("0" to -1L), merged["events-2"])
        assertEquals(50L, (merged["events-1"] as Map<*, *>)["0"])
    }

    fun `test merge does not restore an index the run dropped on purpose`() {
        // The run read events-1, saw its data stream roll over to events-2, and dropped events-1.
        val base = mapOf<String, Any>("events-1" to mapOf("0" to 10L))
        val ours = mapOf<String, Any>("events-2" to mutableMapOf<String, Any>("0" to 5L))
        val theirs = mapOf<String, Any>("events-1" to mapOf("0" to 10L))

        val merged = mergeRunCheckpoints(base, ours, theirs)

        assertFalse(merged.containsKey("events-1"))
        assertEquals(5L, (merged["events-2"] as Map<*, *>)["0"])
    }

    fun `test shard merge leaves descriptive keys as the run saw them`() {
        val merged = mergeShardCheckpoints(
            mapOf("index" to "events-2", "shards_count" to 1, "0" to 3L),
            mapOf("index" to "events-1", "shards_count" to 4, "0" to 1L)
        )
        assertEquals("events-2", merged["index"])
        assertEquals(1, merged["shards_count"])
        assertEquals(3L, merged["0"])
    }
}
