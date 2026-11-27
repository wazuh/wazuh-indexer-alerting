/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.workflow

import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LogEvent
import org.apache.lucene.search.TotalHits
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.mockito.invocation.InvocationOnMock
import org.opensearch.Version
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse
import org.opensearch.action.get.GetResponse
import org.opensearch.action.search.SearchRequest
import org.opensearch.action.search.SearchResponse
import org.opensearch.alerting.AlertService
import org.opensearch.alerting.InputService
import org.opensearch.alerting.MonitorRunnerExecutionContext
import org.opensearch.alerting.WorkflowMetadataService
import org.opensearch.alerting.WorkflowService
import org.opensearch.alerting.alerts.AlertIndices
import org.opensearch.alerting.randomQueryLevelMonitor
import org.opensearch.alerting.randomWorkflow
import org.opensearch.alerting.settings.AlertingSettings
import org.opensearch.alerting.util.isNodeUnavailableFailure
import org.opensearch.cluster.metadata.IndexNameExpressionResolver
import org.opensearch.cluster.node.DiscoveryNode
import org.opensearch.common.logging.Loggers
import org.opensearch.common.settings.ClusterSettings
import org.opensearch.common.settings.Setting
import org.opensearch.common.settings.Settings
import org.opensearch.common.util.concurrent.ThreadContext
import org.opensearch.common.xcontent.XContentFactory
import org.opensearch.commons.alerting.model.Alert
import org.opensearch.commons.alerting.model.DataSources
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.model.ScheduledJob
import org.opensearch.commons.alerting.model.WorkflowRunResult
import org.opensearch.commons.alerting.util.AlertingException
import org.opensearch.core.action.ActionListener
import org.opensearch.core.common.bytes.BytesReference
import org.opensearch.core.common.io.stream.NamedWriteableRegistry
import org.opensearch.core.rest.RestStatus
import org.opensearch.core.xcontent.NamedXContentRegistry
import org.opensearch.core.xcontent.ToXContent
import org.opensearch.index.query.BoolQueryBuilder
import org.opensearch.index.query.TermQueryBuilder
import org.opensearch.node.NodeClosedException
import org.opensearch.script.ScriptService
import org.opensearch.search.SearchHit
import org.opensearch.search.SearchHits
import org.opensearch.test.ClusterServiceUtils
import org.opensearch.test.MockLogAppender
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.threadpool.ThreadPool
import org.opensearch.transport.RemoteTransportException
import org.opensearch.transport.SendRequestTransportException
import org.opensearch.transport.TransportService
import org.opensearch.transport.client.AdminClient
import org.opensearch.transport.client.Client
import org.opensearch.transport.client.IndicesAdminClient
import java.time.Instant

/**
 * Runs a whole workflow on the real alerting services, its delegate monitor succeeding, and fails the block that loads
 * the current chained alerts and runs the chained alert triggers: only a node shutdown is logged below ERROR there.
 *
 * Only the client is fake. The failure reaches the runner the way it does on a node: through the listener of the
 * request the block's first call, the alert index setup, sends.
 */
class CompositeWorkflowRunnerTests : OpenSearchTestCase() {

    private fun node() = DiscoveryNode("node", buildNewFakeTransportAddress(), Version.CURRENT)

    fun `test node closing while chained alerts are processed is not logged as an error`() {
        // wazuh/wazuh-indexer#2175: the node closed while a cluster manager request of that block was waiting.
        val (result, events) = runWorkflowFailingChainedAlertsWith(NodeClosedException(node()))

        assertSkippedAsNodeClosing(events)
        assertTrue(isNodeUnavailableFailure(result.error!!))
    }

    fun `test node closing seen through a transport hop while chained alerts are processed is not logged as an error`() {
        val (result, events) = runWorkflowFailingChainedAlertsWith(
            RemoteTransportException("indices:admin/exists", NodeClosedException(node()))
        )

        assertSkippedAsNodeClosing(events)
        // Plain AlertingException.wrap() would record only the transport wrapper and lose the shutdown.
        assertTrue(isNodeUnavailableFailure(result.error!!))
    }

    fun `test node closing while the alerts index is created is not logged as an error`() {
        // The transport service fails the requests still in flight this way when it stops. The alerts index setup
        // converts the failure of its create request, which must not lose the shutdown.
        val (result, events) = runWorkflowFailingChainedAlertsWith(
            SendRequestTransportException(node(), "indices:admin/create", NodeClosedException(node())),
            alertsIndexMissing = true
        )

        assertSkippedAsNodeClosing(events)
        assertTrue(isNodeUnavailableFailure(result.error!!))
    }

    fun `test any other failure while chained alerts are processed is still logged as an error`() {
        val (result, events) = runWorkflowFailingChainedAlertsWith(IllegalStateException("boom"))

        val errors = events.filter { it.level == Level.ERROR && it.loggerName == RUNNER_LOGGER }
        assertEquals(listOf("Error loading current chained alerts for workflow: $WORKFLOW_ID"), errors.map { it.message })
        assertTrue(events.toString(), events.none { it.message.startsWith("Skipped running chained alert triggers") })
        assertFalse(isNodeUnavailableFailure(result.error!!))
    }

    private fun assertSkippedAsNodeClosing(events: List<CapturedEvent>) {
        assertEquals(emptyList<CapturedEvent>(), events.filter { it.level == Level.ERROR })
        // The line proves the run reached the block's catch, and that the catch took the shutdown branch.
        assertTrue(
            events.toString(),
            events.any {
                it.level == Level.DEBUG && it.loggerName == RUNNER_LOGGER &&
                    it.message == "Skipped running chained alert triggers for workflow $WORKFLOW_ID: node is closing"
            }
        )
    }

    private data class CapturedEvent(val loggerName: String, val level: Level, val message: String)

    /**
     * Runs a workflow with one query-level delegate monitor that succeeds. Once the workflow's current alerts are loaded,
     * the next request for the alerts index -- sent by the first call of the chained alerts block -- fails with [failure]:
     * the check for the index, or, when [alertsIndexMissing], the request that creates it.
     * Gives the run result and every event the runner and `AlertingException.wrap()` logged.
     */
    private fun runWorkflowFailingChainedAlertsWith(
        failure: Exception,
        alertsIndexMissing: Boolean = false
    ): Pair<WorkflowRunResult, List<CapturedEvent>> {
        // An alerts index of its own, as Security Analytics gives its detectors: its setup sends a request every run.
        val dataSources = DataSources(
            alertsIndex = ALERTS_INDEX,
            alertsHistoryIndex = "$ALERTS_INDEX-history",
            alertsHistoryIndexPattern = "<$ALERTS_INDEX-history-{now/d}-1>"
        )
        val monitor = randomQueryLevelMonitor(inputs = emptyList(), triggers = emptyList())
            .copy(id = "monitor-id", dataSources = dataSources)
        val workflow = randomWorkflow(id = WORKFLOW_ID, monitorIds = listOf(monitor.id))
        var workflowAlertsLoaded = false

        val indicesClient = mock(IndicesAdminClient::class.java) { invocation ->
            when {
                invocation.arguments.size != 2 || !workflowAlertsLoaded ->
                    if (invocation.method.name == "exists") invocation.respond(IndicesExistsResponse(true)) else null
                invocation.method.name == "exists" ->
                    if (alertsIndexMissing) invocation.respond(IndicesExistsResponse(false)) else invocation.fail(failure)
                invocation.method.name == "create" -> invocation.fail(failure)
                else -> null
            }
        }
        val adminClient = mock(AdminClient::class.java) { if (it.method.name == "indices") indicesClient else null }
        val client = mock(Client::class.java) { invocation ->
            when {
                invocation.method.name == "admin" -> adminClient
                invocation.arguments.size != 2 -> null
                // No workflow metadata stored yet.
                invocation.method.name == "get" -> invocation.respond(mock(GetResponse::class.java))
                invocation.method.name == "search" -> {
                    val request = invocation.getArgument<SearchRequest>(0)
                    if (request.isWorkflowAlertsSearch()) workflowAlertsLoaded = true
                    invocation.respond(searchResponse(if (ScheduledJob.SCHEDULED_JOBS_INDEX in request.indices()) monitor else null))
                }
                else -> null
            }
        }

        val settings = Settings.EMPTY
        val settingSet = hashSetOf<Setting<*>>()
        settingSet.addAll(ClusterSettings.BUILT_IN_CLUSTER_SETTINGS)
        settingSet.addAll(
            listOf(
                AlertingSettings.ALERT_HISTORY_ENABLED, AlertingSettings.ALERT_HISTORY_MAX_DOCS,
                AlertingSettings.ALERT_HISTORY_INDEX_MAX_AGE, AlertingSettings.ALERT_HISTORY_ROLLOVER_PERIOD,
                AlertingSettings.ALERT_HISTORY_RETENTION_PERIOD, AlertingSettings.REQUEST_TIMEOUT,
                AlertingSettings.FINDING_HISTORY_ENABLED, AlertingSettings.FINDING_HISTORY_MAX_DOCS,
                AlertingSettings.FINDING_HISTORY_INDEX_MAX_AGE, AlertingSettings.FINDING_HISTORY_ROLLOVER_PERIOD,
                AlertingSettings.FINDING_HISTORY_RETENTION_PERIOD, AlertingSettings.INDEX_TIMEOUT,
                AlertingSettings.MAX_COMMENTS_PER_NOTIFICATION
            )
        )
        val threadContext = ThreadContext(settings)
        val threadPool = mock(ThreadPool::class.java) { if (it.method.name == "getThreadContext") threadContext else null }
        val clusterService = ClusterServiceUtils.createClusterService(threadPool, node(), ClusterSettings(settings, settingSet))
        // The monitor has no inputs nor triggers, so parsing it from the scheduled jobs index needs nothing else.
        val registry = NamedXContentRegistry(listOf(Monitor.XCONTENT_REGISTRY))
        WorkflowMetadataService.initialize(client, clusterService, registry, settings)
        val alertIndices = AlertIndices(settings, client, threadPool, clusterService)
        val monitorCtx = MonitorRunnerExecutionContext(
            clusterService = clusterService,
            client = client,
            xContentRegistry = registry,
            settings = settings,
            threadPool = threadPool,
            alertIndices = alertIndices,
            alertService = AlertService(client, registry, alertIndices),
            workflowService = WorkflowService(client, registry),
            inputService = InputService(
                client, mock(ScriptService::class.java), NamedWriteableRegistry(emptyList()), registry, clusterService, settings,
                mock(IndexNameExpressionResolver::class.java)
            )
        )

        val events = mutableListOf<CapturedEvent>()
        val loggers = listOf(LogManager.getLogger(CompositeWorkflowRunner::class.java), LogManager.getLogger(AlertingException::class.java))
        val previousLevels = loggers.map { it.level }
        loggers.forEach { Loggers.setLevel(it, Level.DEBUG) }
        try {
            val result = MockLogAppender.createForLoggers(*loggers.toTypedArray()).use { appender ->
                appender.addExpectation(object : MockLogAppender.LoggingExpectation {
                    override fun match(event: LogEvent) {
                        events.add(CapturedEvent(event.loggerName, event.level, event.message.formattedMessage))
                    }

                    override fun assertMatched() {}
                })
                runBlocking {
                    CompositeWorkflowRunner.runWorkflow(
                        workflow, monitorCtx, Instant.now().minusSeconds(60), Instant.now(), true, mock(TransportService::class.java)
                    )
                }
            }
            // The delegate monitor and the workflow's alerts loaded, so the failure came from the chained alerts block.
            assertTrue("the workflow's current alerts were never loaded: $events", workflowAlertsLoaded)
            return result to events
        } finally {
            loggers.zip(previousLevels).forEach { (logger, level) -> Loggers.setLevel(logger, level) }
            clusterService.close()
        }
    }

    /** The search `AlertService.loadCurrentAlertsForWorkflow()` sends: the workflow's own alerts carry no monitor id. */
    private fun SearchRequest.isWorkflowAlertsSearch(): Boolean =
        (source()?.query() as? BoolQueryBuilder)?.must()?.any {
            it is TermQueryBuilder && it.fieldName() == Alert.MONITOR_ID_FIELD && it.value() == ""
        } == true

    /** A search response with [monitor] as its only hit, as the scheduled jobs index gives it, or no hit. */
    private fun searchResponse(monitor: Monitor?): SearchResponse {
        val hits = listOfNotNull(monitor).map {
            val source = it.toXContentWithUser(XContentFactory.jsonBuilder(), ToXContent.MapParams(mapOf("with_type" to "true")))
            SearchHit(0, it.id, emptyMap(), emptyMap()).sourceRef(BytesReference.bytes(source)).also { hit -> hit.version(1L) }
        }
        val response = mock(SearchResponse::class.java)
        `when`(response.status()).thenReturn(RestStatus.OK)
        `when`(response.hits).thenReturn(SearchHits(hits.toTypedArray(), TotalHits(hits.size.toLong(), TotalHits.Relation.EQUAL_TO), 1f))
        return response
    }

    /** Answers the action listener of a mocked client call. */
    private fun <T> InvocationOnMock.respond(response: T): Any? {
        getArgument<ActionListener<T>>(arguments.size - 1).onResponse(response)
        return null
    }

    /** Fails the action listener of a mocked client call. */
    private fun InvocationOnMock.fail(failure: Exception): Any? {
        getArgument<ActionListener<Any>>(arguments.size - 1).onFailure(failure)
        return null
    }

    companion object {
        private const val WORKFLOW_ID = "workflow-id"
        private const val ALERTS_INDEX = ".opensearch-sap-test-alerts"
        private val RUNNER_LOGGER = CompositeWorkflowRunner::class.java.name
    }
}
