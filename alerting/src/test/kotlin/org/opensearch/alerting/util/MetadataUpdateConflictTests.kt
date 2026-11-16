/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import kotlinx.coroutines.runBlocking
import org.opensearch.commons.alerting.model.MonitorMetadata
import org.opensearch.commons.alerting.util.AlertingException
import org.opensearch.core.rest.RestStatus
import org.opensearch.test.OpenSearchTestCase

/**
 * Tests how an index monitor or index workflow request stores its metadata when a monitor run checkpoints
 * the same document in the meantime (wazuh/wazuh-indexer#2108).
 */
class MetadataUpdateConflictTests : OpenSearchTestCase() {

    private fun metadata(
        seqNo: Long,
        lastRunContext: Map<String, Any>,
        mapping: Map<String, String> = mapOf("events-1mon" to "queries-000001"),
    ) = MonitorMetadata(
        id = "wf-metadata-mon-metadata",
        seqNo = seqNo,
        primaryTerm = 1L,
        monitorId = "mon",
        lastActionExecutionTimes = emptyList(),
        lastRunContext = lastRunContext,
        sourceToQueryIndexMapping = LinkedHashMap(mapping)
    )

    private fun checkpoint(seqNo: Long): Map<String, Any> = mapOf("index" to "events-1", "shards_count" to 1, "0" to seqNo)

    /** A stored metadata document whose writes fail on a stale sequence number, as the job index does. */
    private class FakeStore(var stored: MonitorMetadata) {
        val writes = mutableListOf<MonitorMetadata>()
        val write: suspend (MonitorMetadata) -> MonitorMetadata? = { metadata ->
            if (metadata.seqNo != stored.seqNo) {
                null
            } else {
                writes.add(metadata)
                stored = metadata.copy(seqNo = stored.seqNo + 1)
                stored
            }
        }
        val read: suspend () -> MonitorMetadata? = { stored }
    }

    fun `test reapply keeps the run's checkpoint and adds the indices the update gained`() {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        val current = metadata(2, mapOf("events-1" to checkpoint(40)))

        val reapplied = reapplyMetadataUpdate(current, base, update, resetRunContext = false)

        assertEquals(2L, reapplied.seqNo)
        assertEquals(checkpoint(40), reapplied.lastRunContext["events-1"])
        assertEquals(checkpoint(-1), reapplied.lastRunContext["events-2"])
    }

    fun `test reapply does not restore an index the run dropped`() {
        // The update read events-1; a run then dropped it after its data stream rolled over to events-2.
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10)))
        val current = metadata(2, mapOf("events-2" to checkpoint(3)))

        val reapplied = reapplyMetadataUpdate(current, base, update, resetRunContext = false)

        assertEquals(mapOf<String, Any>("events-2" to checkpoint(3)), reapplied.lastRunContext)
    }

    fun `test reapply of a re-enable replaces the run context`() {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(90)))
        val current = metadata(2, mapOf("events-1" to checkpoint(40)))

        val reapplied = reapplyMetadataUpdate(current, base, update, resetRunContext = true)

        assertEquals(update.lastRunContext, reapplied.lastRunContext)
        assertEquals(2L, reapplied.seqNo)
    }

    fun `test reapply applies only the query index mapping entries the update changed`() {
        val base = metadata(1, emptyMap(), mapOf("events-1mon" to "queries-000001", "events-2mon" to "queries-000001"))
        // The update moved events-1 to a new query index, dropped events-2 and added events-3.
        val update = metadata(1, emptyMap(), mapOf("events-1mon" to "queries-000002", "events-3mon" to "queries-000002"))
        // A run meanwhile registered events-4.
        val current = metadata(
            2,
            emptyMap(),
            mapOf("events-1mon" to "queries-000001", "events-2mon" to "queries-000001", "events-4mon" to "queries-000001")
        )

        val reapplied = reapplyMetadataUpdate(current, base, update, resetRunContext = false)

        assertEquals(
            mapOf("events-1mon" to "queries-000002", "events-3mon" to "queries-000002", "events-4mon" to "queries-000001"),
            reapplied.sourceToQueryIndexMapping
        )
    }

    fun `test write without a conflict stores the update as computed`() = runBlocking {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        val store = FakeStore(base)

        writeMetadataReapplyingOnConflict(update, 5, store.write, store.read) { reapplyMetadataUpdate(it, base, update, false) }

        assertEquals(listOf(update), store.writes)
    }

    fun `test update that loses the race to a run checkpoint is re-applied and stored`() = runBlocking {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        // A run checkpointed events-1 after the update read the document.
        val store = FakeStore(metadata(2, mapOf("events-1" to checkpoint(40))))

        val stored = writeMetadataReapplyingOnConflict(update, 5, store.write, store.read) {
            reapplyMetadataUpdate(it, base, update, false)
        }

        assertEquals(1, store.writes.size)
        assertEquals(checkpoint(40), stored.lastRunContext["events-1"])
        assertEquals(checkpoint(-1), stored.lastRunContext["events-2"])
    }

    fun `test nothing is written when the stored copy already holds the update`() = runBlocking {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        val store = FakeStore(metadata(2, mapOf("events-1" to checkpoint(40), "events-2" to checkpoint(5))))

        val stored = writeMetadataReapplyingOnConflict(update, 5, store.write, store.read) {
            reapplyMetadataUpdate(it, base, update, false)
        }

        assertTrue(store.writes.isEmpty())
        assertEquals(store.stored, stored)
    }

    fun `test update gives up with a conflict when the document keeps moving`() {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        val store = FakeStore(metadata(2, mapOf("events-1" to checkpoint(40))))
        var reads = 0
        val movingRead: suspend () -> MonitorMetadata? = {
            reads++
            // Another run checkpoints between every read and write.
            store.stored = store.stored.copy(seqNo = store.stored.seqNo + 1)
            store.stored.copy(seqNo = store.stored.seqNo - 1)
        }

        val e = expectThrows(AlertingException::class.java) {
            runBlocking {
                writeMetadataReapplyingOnConflict(update, 3, store.write, movingRead) { reapplyMetadataUpdate(it, base, update, false) }
            }
        }

        assertEquals(RestStatus.CONFLICT, e.status())
        assertEquals(2, reads)
        assertTrue(store.writes.isEmpty())
    }

    fun `test update fails when the metadata document is gone`() {
        val base = metadata(1, mapOf("events-1" to checkpoint(10)))
        val update = metadata(1, mapOf("events-1" to checkpoint(10), "events-2" to checkpoint(-1)))
        val store = FakeStore(metadata(2, mapOf("events-1" to checkpoint(40))))

        val e = expectThrows(AlertingException::class.java) {
            runBlocking {
                writeMetadataReapplyingOnConflict(update, 5, store.write, { null }) { reapplyMetadataUpdate(it, base, update, false) }
            }
        }

        assertEquals(RestStatus.NOT_FOUND, e.status())
    }

    fun `test own query index mapping is not shared with the original`() {
        val original = metadata(1, emptyMap())
        val copy = original.withOwnQueryIndexMapping()

        original.sourceToQueryIndexMapping["events-9mon"] = "queries-000009"

        assertFalse(copy.sourceToQueryIndexMapping.containsKey("events-9mon"))
    }
}
