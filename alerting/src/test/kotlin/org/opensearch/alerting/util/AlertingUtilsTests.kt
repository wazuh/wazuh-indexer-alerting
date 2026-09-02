/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.mockito.Mockito.mock
import org.opensearch.OpenSearchException
import org.opensearch.Version
import org.opensearch.alerting.AlertService
import org.opensearch.alerting.MonitorRunnerService
import org.opensearch.alerting.model.AlertContext
import org.opensearch.alerting.randomAction
import org.opensearch.alerting.randomBucketLevelTrigger
import org.opensearch.alerting.randomChainedAlertTrigger
import org.opensearch.alerting.randomDocumentLevelTrigger
import org.opensearch.alerting.randomQueryLevelTrigger
import org.opensearch.alerting.randomTemplateScript
import org.opensearch.alerting.script.BucketLevelTriggerExecutionContext
import org.opensearch.alerting.script.DocumentLevelTriggerExecutionContext
import org.opensearch.cluster.node.DiscoveryNode
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.unit.TimeValue
import org.opensearch.commons.alerting.util.AlertingException
import org.opensearch.node.NodeClosedException
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.NodeNotConnectedException
import org.opensearch.transport.RemoteTransportException
import org.opensearch.transport.client.Client
import java.io.IOException
class AlertingUtilsTests : OpenSearchTestCase() {
    fun `test parseSampleDocTags only returns expected tags`() {
        val expectedDocSourceTags = (0..3).map { "field$it" }
        val unexpectedDocSourceTags = ((expectedDocSourceTags.size + 1)..(expectedDocSourceTags.size + 5))
            .map { "field$it" }

        val unexpectedTagsScriptSource = unexpectedDocSourceTags.joinToString { field -> "$field = {{$field}}" }
        val expectedTagsScriptSource = unexpectedTagsScriptSource + """
                ${unexpectedDocSourceTags.joinToString("\n") { field -> "$field = {{$field}}" }}
                {{#alerts}}
                {{#${AlertContext.SAMPLE_DOCS_FIELD}}}
                    ${expectedDocSourceTags.joinToString("\n") { field -> "$field = {{_source.$field}}" }}
                {{/${AlertContext.SAMPLE_DOCS_FIELD}}}
                {{/alerts}}
        """.trimIndent()

        // Action that prints doc source data
        val trigger1 = randomDocumentLevelTrigger(
            actions = listOf(randomAction(template = randomTemplateScript(source = expectedTagsScriptSource)))
        )

        // Action that does not print doc source data
        val trigger2 = randomDocumentLevelTrigger(
            actions = listOf(randomAction(template = randomTemplateScript(source = unexpectedTagsScriptSource)))
        )

        // No actions
        val trigger3 = randomDocumentLevelTrigger(actions = listOf())

        val tags = parseSampleDocTags(listOf(trigger1, trigger2, trigger3))

        assertEquals(expectedDocSourceTags.size, tags.size)
        expectedDocSourceTags.forEach { tag -> assertTrue(tags.contains(tag)) }
        unexpectedDocSourceTags.forEach { tag -> assertFalse(tags.contains(tag)) }
    }

    fun `test printsSampleDocData entire ctx tag returns TRUE`() {
        val tag = "{{ctx}}"
        val triggers = listOf(
            randomBucketLevelTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag)))),
            randomDocumentLevelTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag))))
        )

        triggers.forEach { trigger -> assertTrue(printsSampleDocData(trigger)) }
    }

    fun `test printsSampleDocData entire alerts tag returns TRUE`() {
        val triggers = listOf(
            randomBucketLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = "{{ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}"
                        )
                    )
                )
            ),
            randomDocumentLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = "{{ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}"
                        )
                    )
                )
            )
        )

        triggers.forEach { trigger -> assertTrue(printsSampleDocData(trigger)) }
    }

    fun `test printsSampleDocData entire sample_docs tag returns TRUE`() {
        val triggers = listOf(
            randomBucketLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = """
                                {{#ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}
                                    {{${AlertContext.SAMPLE_DOCS_FIELD}}}
                                {{/ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}
                            """.trimIndent()
                        )
                    )
                )
            ),
            randomDocumentLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = """
                                {{#ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}
                                    {{${AlertContext.SAMPLE_DOCS_FIELD}}}
                                {{/ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}
                            """.trimIndent()
                        )
                    )
                )
            )
        )

        triggers.forEach { trigger -> assertTrue(printsSampleDocData(trigger)) }
    }

    fun `test printsSampleDocData sample_docs iteration block returns TRUE`() {
        val triggers = listOf(
            randomBucketLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = """
                                {{#ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}
                                    "{{#${AlertContext.SAMPLE_DOCS_FIELD}}}"
                                        {{_source.field}}
                                    "{{/${AlertContext.SAMPLE_DOCS_FIELD}}}"
                                {{/ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}
                            """.trimIndent()
                        )
                    )
                )
            ),
            randomDocumentLevelTrigger(
                actions = listOf(
                    randomAction(
                        template = randomTemplateScript(
                            source = """
                                {{#ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}
                                    {{#${AlertContext.SAMPLE_DOCS_FIELD}}}
                                        {{_source.field}}
                                    {{/${AlertContext.SAMPLE_DOCS_FIELD}}}
                                {{/ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}
                            """.trimIndent()
                        )
                    )
                )
            )
        )

        triggers.forEach { trigger -> assertTrue(printsSampleDocData(trigger)) }
    }

    fun `test printsSampleDocData unrelated tag returns FALSE`() {
        val tag = "{{ctx.monitor.name}}"
        val triggers = listOf(
            randomBucketLevelTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag)))),
            randomDocumentLevelTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag))))
        )

        triggers.forEach { trigger -> assertFalse(printsSampleDocData(trigger)) }
    }

    fun `test printsSampleDocData unsupported trigger types return FALSE`() {
        val tag = "{{ctx}}"
        val triggers = listOf(
            randomQueryLevelTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag)))),
            randomChainedAlertTrigger(actions = listOf(randomAction(template = randomTemplateScript(source = tag))))
        )

        triggers.forEach { trigger -> assertFalse(printsSampleDocData(trigger)) }
    }

    fun `test getCancelAfterTimeInterval returns -1 when setting is default`() {
        val original = MonitorRunnerService.monitorCtx.cancelAfterTimeInterval
        try {
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = TimeValue.timeValueMinutes(-1)
            assertEquals(-1L, getCancelAfterTimeInterval())
        } finally {
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = original
        }
    }

    fun `test getCancelAfterTimeInterval returns at least ALERTS_SEARCH_TIMEOUT`() {
        val original = MonitorRunnerService.monitorCtx.cancelAfterTimeInterval
        try {
            // Setting lower than ALERTS_SEARCH_TIMEOUT (5 min) should return 5 min
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = TimeValue.timeValueMinutes(1)
            assertEquals(AlertService.ALERTS_SEARCH_TIMEOUT.minutes, getCancelAfterTimeInterval())
        } finally {
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = original
        }
    }

    fun `test getCancelAfterTimeInterval returns setting when higher than ALERTS_SEARCH_TIMEOUT`() {
        val original = MonitorRunnerService.monitorCtx.cancelAfterTimeInterval
        try {
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = TimeValue.timeValueMinutes(10)
            assertEquals(10L, getCancelAfterTimeInterval())
        } finally {
            MonitorRunnerService.monitorCtx.cancelAfterTimeInterval = original
        }
    }

    fun `test traverseMappingsAndUpdate with nested field type without properties succeeds`() {
        // Verifies fix for https://github.com/opensearch-project/security-analytics/issues/1472
        val docLevelMonitorQueries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))
        val mappings = mutableMapOf<String, Any>(
            "message" to mutableMapOf<String, Any>("type" to "text"),
            "http_request_headers" to mutableMapOf<String, Any>("type" to "nested")
        )
        val flattenPaths = mutableMapOf<String, MutableMap<String, Any>>()
        val leafProcessor =
            fun(fieldName: String, _: String, props: MutableMap<String, Any>):
                Triple<String, String, MutableMap<String, Any>> {
                return Triple(fieldName, fieldName, props)
            }

        docLevelMonitorQueries.traverseMappingsAndUpdate(mappings, "", leafProcessor, flattenPaths)

        assertTrue("Expected 'message' in flatten paths", flattenPaths.containsKey("message"))
        assertFalse("Expected nested field to be skipped", flattenPaths.containsKey("http_request_headers"))
    }

    fun `test traverseMappingsAndUpdate with nested field type with properties works`() {
        val docLevelMonitorQueries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))
        val mappings = mutableMapOf<String, Any>(
            "message" to mutableMapOf<String, Any>("type" to "text"),
            "dll" to mutableMapOf<String, Any>(
                "type" to "nested",
                "properties" to mutableMapOf<String, Any>(
                    "name" to mutableMapOf<String, Any>("type" to "keyword")
                )
            )
        )
        val flattenPaths = mutableMapOf<String, MutableMap<String, Any>>()
        val leafProcessor =
            fun(fieldName: String, _: String, props: MutableMap<String, Any>):
                Triple<String, String, MutableMap<String, Any>> {
                return Triple(fieldName, fieldName, props)
            }

        docLevelMonitorQueries.traverseMappingsAndUpdate(mappings, "", leafProcessor, flattenPaths)

        assertTrue("Expected 'message' in flatten paths", flattenPaths.containsKey("message"))
        assertTrue("Expected 'dll.name' in flatten paths", flattenPaths.containsKey("dll.name"))
    }

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

    fun `test node closed exception already converted to an AlertingException is a node unavailable failure`() {
        // AlertIndices.createIndex() throws AlertingException.wrap(t), so the callers above it never
        // see the NodeClosedException itself: wrap() flattens it to Exception("<class name>: <msg>")
        // and AlertingException is not an OpenSearchWrapperException, so unwrapCause() stops there.
        val converted = AlertingException.wrap(NodeClosedException(node())) as Exception

        assertTrue(isNodeUnavailableFailure(converted))
    }

    fun `test converted node closed exception is recognised through a transport hop`() {
        val converted = AlertingException.wrap(NodeClosedException(node())) as Exception
        val wrapped = RemoteTransportException("indices:admin/create", converted)

        assertTrue(isNodeUnavailableFailure(wrapped))
    }

    fun `test converted genuine failure is not a node unavailable failure`() {
        val converted = AlertingException.wrap(IllegalStateException("boom")) as Exception

        assertFalse(isNodeUnavailableFailure(converted))
    }
}
