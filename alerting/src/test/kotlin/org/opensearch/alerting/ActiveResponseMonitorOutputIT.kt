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

    fun `test active response monitor emits wazuh-shaped doc to wazuh-active-responses`() {
        val sourceIndex = "wazuh-findings-v5-test-${randomAlphaOfLength(6).lowercase()}"
        // Source-doc mapping covers the fields the AR write reads (wazuh.agent.*) and the doc-level query (rule.level).
        createTestIndex(
            sourceIndex,
            """
            "properties" : {
              "rule" : { "properties" : { "level" : { "type" : "integer" } } },
              "wazuh" : {
                "properties" : {
                  "agent" : {
                    "properties" : {
                      "id" : { "type" : "keyword" },
                      "name" : { "type" : "keyword" }
                    }
                  },
                  "cluster" : {
                    "properties" : { "name" : { "type" : "keyword" } }
                  }
                }
              }
            }
            """.trimIndent()
        )

        // Pre-create the destination index. In production, this alias maps to a data stream owned by
        // another Wazuh plugin; the test substitutes a plain index because the data stream template
        // is not installed in the alerting integTest cluster.
        adminClient().makeRequest("PUT", "/$arWriteAlias")

        val testDoc = """
            {
              "rule" : { "level" : 10 },
              "wazuh" : {
                "agent" : { "id" : "001", "name" : "agent-alpha" },
                "cluster" : { "name" : "wazuh-cluster" }
              }
            }
        """.trimIndent()
        indexDoc(sourceIndex, "src-1", testDoc)

        val docQuery = DocLevelQuery(query = "rule.level:>=10", name = "high_severity", fields = listOf())
        val docLevelInput = DocLevelMonitorInput("description", listOf(sourceIndex), listOf(docQuery))
        val triggerName = "block-agent"
        val trigger = randomDocumentLevelTrigger(name = triggerName, condition = ALWAYS_RUN)

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

        // AR path skips the synchronous refresh in bulkIndexFindings — refresh explicitly to read back.
        refreshIndex(arWriteAlias)
        val arHits = searchHits(arWriteAlias, """{ "query" : { "match_all" : {} } }""")
        assertEquals("Expected exactly one AR doc in $arWriteAlias", 1, arHits.size)

        @Suppress("UNCHECKED_CAST")
        val doc = arHits.first()
        assertNotNull("Missing @timestamp", doc["@timestamp"])
        val event = doc["event"] as Map<String, Any>
        assertEquals("src-1", event["doc_id"])
        assertEquals(sourceIndex, event["index"])
        val wazuh = doc["wazuh"] as Map<String, Any>
        val activeResponse = wazuh["active_response"] as Map<String, Any>
        assertEquals(triggerName, activeResponse["name"])
        val agent = wazuh["agent"] as Map<String, Any>
        assertEquals("001", agent["id"])
        assertEquals("agent-alpha", agent["name"])

        // Findings history must remain empty — AR persists only the Wazuh doc, not Findings.
        val findingsHits = countHitsByMonitorId(AlertIndices.ALL_FINDING_INDEX_PATTERN, monitor.id)
        assertEquals("AR monitor must not write to the findings history index", 0, findingsHits)

        // Alerts ARE created so AR firings surface via GET /_plugins/_alerting/monitors/alerts.
        val alertHits = countHitsByMonitorId(AlertIndices.ALERT_INDEX, monitor.id)
        assertEquals("AR monitor should produce one alert per triggered doc", 1, alertHits)
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

    @Suppress("UNCHECKED_CAST")
    private fun searchHits(index: String, body: String): List<Map<String, Any>> {
        val response = adminClient().makeRequest(
            "GET", "/$index/_search?ignore_unavailable=true",
            StringEntity(body, ContentType.APPLICATION_JSON)
        )
        assertEquals("Search failed on $index", RestStatus.OK, response.restStatus())
        val parser = createParser(JsonXContent.jsonXContent, response.entity.content)
        val searchResponse = SearchResponse.fromXContent(parser)
        return searchResponse.hits.hits.map { it.sourceAsMap as Map<String, Any> }
    }

    private fun countHitsByMonitorId(index: String, monitorId: String): Int {
        val body = """
            { "query" : { "term" : { "monitor_id" : "$monitorId" } } }
        """.trimIndent()
        val response = adminClient().makeRequest(
            "GET", "/$index/_search?ignore_unavailable=true",
            StringEntity(body, ContentType.APPLICATION_JSON)
        )
        assertEquals("Search failed on $index", RestStatus.OK, response.restStatus())
        val parser = createParser(JsonXContent.jsonXContent, response.entity.content)
        return SearchResponse.fromXContent(parser).hits.hits.size
    }
}
