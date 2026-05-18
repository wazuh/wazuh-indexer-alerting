/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting

import org.apache.hc.core5.http.ContentType
import org.apache.hc.core5.http.io.entity.StringEntity
import org.opensearch.action.search.SearchResponse
import org.opensearch.alerting.alerts.AlertIndices
import org.opensearch.client.ResponseException
import org.opensearch.common.xcontent.json.JsonXContent
import org.opensearch.commons.alerting.model.DocLevelMonitorInput
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.commons.alerting.model.IntervalSchedule
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.core.rest.RestStatus
import java.time.Instant
import java.time.temporal.ChronoUnit

class ActiveResponseMonitorOutputIT : AlertingRestTestCase() {

    private val arWriteAlias = AlertIndices.WAZUH_ACTIVE_RESPONSES_WRITE_ALIAS

    fun `test active response monitor writes to wazuh-active-responses and skips findings and alerts`() {
        val sourceIndex = "wazuh-findings-v5-test-${randomAlphaOfLength(6).lowercase()}"
        createTestIndex(
            sourceIndex,
            """
            "properties" : {
              "rule" : {
                "properties" : {
                  "level" : { "type" : "integer" }
                }
              }
            }
            """.trimIndent()
        )

        // Pre-create the AR destination index. In production this alias is owned by another
        // Wazuh plugin; here we seed it explicitly so the write isn't relying on auto-create.
        adminClient().makeRequest("PUT", "/$arWriteAlias")

        val testDoc = """{ "rule" : { "level" : 10 } }"""
        indexDoc(sourceIndex, "1", testDoc)

        val docQuery = DocLevelQuery(query = "rule.level:>=10", name = "high_severity", fields = listOf())
        val docLevelInput = DocLevelMonitorInput("description", listOf(sourceIndex), listOf(docQuery))
        val trigger = randomDocumentLevelTrigger(condition = ALWAYS_RUN)

        val arMonitor = Monitor(
            name = "ar-output-it-${randomAlphaOfLength(5)}",
            monitorType = Monitor.MonitorType.ACTIVE_RESPONSE_MONITOR.value,
            enabled = true,
            inputs = listOf(docLevelInput),
            schedule = IntervalSchedule(interval = 1, unit = ChronoUnit.MINUTES),
            triggers = listOf(trigger),
            enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS),
            lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS),
            user = randomUser(),
            uiMetadata = mapOf()
        )

        val monitor = createMonitor(arMonitor)
        assertNotNull(monitor.id)

        executeMonitor(monitor.id)

        // AR path skips the synchronous refresh in bulkIndexFindings, so refresh explicitly before asserting.
        refreshIndex(arWriteAlias)
        val arHits = searchHitsByMonitorId(arWriteAlias, monitor.id)
        assertEquals("AR doc was not written to $arWriteAlias", 1, arHits)

        // Findings history index must be empty for this monitor.
        val findingsHits = searchHitsByMonitorId(AlertIndices.ALL_FINDING_INDEX_PATTERN, monitor.id)
        assertEquals("AR monitor must not write to the findings history index", 0, findingsHits)

        // Alert index must contain no doc-level alerts for this monitor.
        val alertHits = searchHitsByMonitorId(AlertIndices.ALERT_INDEX, monitor.id)
        assertEquals("AR monitor must not produce alerts", 0, alertHits)
    }

    fun `test active response monitor rejects shouldCreateSingleAlertForFindings`() {
        val sourceIndex = "wazuh-findings-v5-test-${randomAlphaOfLength(6).lowercase()}"
        createTestIndex(sourceIndex)

        val docQuery = DocLevelQuery(query = "test_field:\"x\"", name = "q", fields = listOf())
        val docLevelInput = DocLevelMonitorInput("description", listOf(sourceIndex), listOf(docQuery))
        val trigger = randomDocumentLevelTrigger(condition = ALWAYS_RUN)

        val invalidMonitor = Monitor(
            name = "ar-bad-${randomAlphaOfLength(5)}",
            monitorType = Monitor.MonitorType.ACTIVE_RESPONSE_MONITOR.value,
            enabled = true,
            inputs = listOf(docLevelInput),
            schedule = IntervalSchedule(interval = 1, unit = ChronoUnit.MINUTES),
            triggers = listOf(trigger),
            enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS),
            lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS),
            user = randomUser(),
            uiMetadata = mapOf(),
            shouldCreateSingleAlertForFindings = true
        )

        try {
            createMonitor(invalidMonitor)
            fail("Expected validation failure for shouldCreateSingleAlertForFindings=true on AR monitor")
        } catch (e: ResponseException) {
            assertEquals(RestStatus.BAD_REQUEST, e.response.restStatus())
            assertTrue(
                "Unexpected error: ${e.message}",
                e.message!!.contains("shouldCreateSingleAlertForFindings", ignoreCase = true)
            )
        }
    }

    private fun searchHitsByMonitorId(index: String, monitorId: String): Int {
        val body = """
            { "query" : { "term" : { "monitor_id" : "$monitorId" } } }
        """.trimIndent()
        val response = adminClient().makeRequest(
            "GET", "/$index/_search?ignore_unavailable=true",
            StringEntity(body, ContentType.APPLICATION_JSON)
        )
        assertEquals("Search failed on $index", RestStatus.OK, response.restStatus())
        val parser = createParser(JsonXContent.jsonXContent, response.entity.content)
        val searchResponse = SearchResponse.fromXContent(parser)
        return searchResponse.hits.hits.size
    }
}
