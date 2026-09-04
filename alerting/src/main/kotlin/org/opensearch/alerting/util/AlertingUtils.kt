/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.apache.logging.log4j.LogManager
import org.opensearch.action.search.SearchPhaseExecutionException
import org.opensearch.alerting.AlertService
import org.opensearch.alerting.MonitorRunnerService
import org.opensearch.alerting.model.AlertContext
import org.opensearch.alerting.model.destination.Destination
import org.opensearch.alerting.script.BucketLevelTriggerExecutionContext
import org.opensearch.alerting.script.DocumentLevelTriggerExecutionContext
import org.opensearch.alerting.settings.DestinationSettings
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.settings.Settings
import org.opensearch.common.util.concurrent.ThreadContext
import org.opensearch.commons.alerting.model.AggregationResultBucket
import org.opensearch.commons.alerting.model.BucketLevelTrigger
import org.opensearch.commons.alerting.model.BucketLevelTriggerRunResult
import org.opensearch.commons.alerting.model.DocumentLevelTrigger
import org.opensearch.commons.alerting.model.Monitor
import org.opensearch.commons.alerting.model.Trigger
import org.opensearch.commons.alerting.model.action.Action
import org.opensearch.commons.alerting.model.action.ActionExecutionPolicy
import org.opensearch.commons.alerting.model.action.ActionExecutionScope
import org.opensearch.commons.alerting.util.isBucketLevelMonitor
import org.opensearch.commons.alerting.util.isMonitorOfStandardType
import org.opensearch.core.common.breaker.CircuitBreakingException
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException
import org.opensearch.core.tasks.TaskCancelledException
import org.opensearch.node.NodeClosedException
import org.opensearch.script.Script
import org.opensearch.transport.NodeNotConnectedException
import java.util.Locale
import kotlin.math.max

private val logger = LogManager.getLogger("AlertingUtils")

val MAX_SEARCH_SIZE = 10000

/**
 * RFC 5322 compliant pattern matching: https://www.ietf.org/rfc/rfc5322.txt
 * Regex was based off of this post: https://stackoverflow.com/a/201378
 */
fun isValidEmail(email: String): Boolean {
    val validEmailPattern = Regex(
        "(?:[a-z0-9!#\$%&'*+\\/=?^_`{|}~-]+(?:\\.[a-z0-9!#\$%&'*+\\/=?^_`{|}~-]+)*" +
            "|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")" +
            "@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" +
            "|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}" +
            "(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:" +
            "(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])",
        RegexOption.IGNORE_CASE
    )

    return validEmailPattern.matches(email)
}

fun getRoleFilterEnabled(clusterService: ClusterService, settings: Settings, settingPath: String): Boolean {
    var adBackendRoleFilterEnabled: Boolean
    val metaData = clusterService.state().metadata()

    // get default value for setting
    if (clusterService.clusterSettings.get(settingPath) != null) {
        adBackendRoleFilterEnabled = clusterService.clusterSettings.get(settingPath).getDefault(settings) as Boolean
    } else {
        // default setting doesn't exist, so returning false as it means AD plugins isn't in cluster anyway
        return false
    }

    // Transient settings are prioritized so those are checked first.
    return if (metaData.transientSettings().get(settingPath) != null) {
        metaData.transientSettings().getAsBoolean(settingPath, adBackendRoleFilterEnabled)
    } else if (metaData.persistentSettings().get(settingPath) != null) {
        metaData.persistentSettings().getAsBoolean(settingPath, adBackendRoleFilterEnabled)
    } else {
        adBackendRoleFilterEnabled
    }
}

/** Allowed Destinations are ones that are specified in the [DestinationSettings.ALLOW_LIST] setting. */
fun Destination.isAllowed(allowList: List<String>): Boolean = allowList.contains(this.type.value)

fun Destination.isTestAction(): Boolean = this.type == DestinationType.TEST_ACTION

fun Monitor.isDocLevelMonitor(): Boolean =
    this.isMonitorOfStandardType() &&
        Monitor.MonitorType.valueOf(this.monitorType.uppercase(Locale.ROOT)) == Monitor.MonitorType.DOC_LEVEL_MONITOR

fun Monitor.isQueryLevelMonitor(): Boolean =
    this.isMonitorOfStandardType() &&
        Monitor.MonitorType.valueOf(this.monitorType.uppercase(Locale.ROOT)) == Monitor.MonitorType.QUERY_LEVEL_MONITOR

fun Monitor.isActiveResponseMonitor(): Boolean =
    this.isMonitorOfStandardType() &&
        Monitor.MonitorType.valueOf(this.monitorType.uppercase(Locale.ROOT)) == Monitor.MonitorType.ACTIVE_RESPONSE_MONITOR

/**
 * Since buckets can have multi-value keys, this converts the bucket key values to a string that can be used
 * as the key for a HashMap to easily retrieve [AggregationResultBucket] based on the bucket key values.
 */
fun AggregationResultBucket.getBucketKeysHash(): String = getBucketKeysHash(this.bucketKeys)

fun getBucketKeysHash(bucketKeys: List<String>): String = bucketKeys.joinToString(separator = "#")

fun Action.getActionExecutionPolicy(monitor: Monitor): ActionExecutionPolicy? {
    // When the ActionExecutionPolicy is null for an Action, the default is resolved at runtime
    // so it can be chosen based on the Monitor type at that time.
    // The Action config is not aware of the Monitor type which is why the default was not stored during
    // the parse.
    return this.actionExecutionPolicy ?: if (monitor.isBucketLevelMonitor()) {
        ActionExecutionPolicy.getDefaultConfigurationForBucketLevelMonitor()
    } else if (monitor.isDocLevelMonitor()) {
        ActionExecutionPolicy.getDefaultConfigurationForDocumentLevelMonitor()
    } else {
        null
    }
}

fun BucketLevelTriggerRunResult.getCombinedTriggerRunResult(
    prevTriggerRunResult: BucketLevelTriggerRunResult?
): BucketLevelTriggerRunResult {
    if (prevTriggerRunResult == null) return this

    // The aggregation results and action results across to two trigger run results should not have overlapping keys
    // since they represent different pages of aggregations so a simple concatenation will combine them
    val mergedAggregationResultBuckets = prevTriggerRunResult.aggregationResultBuckets + this.aggregationResultBuckets
    val mergedActionResultsMap = (prevTriggerRunResult.actionResultsMap + this.actionResultsMap).toMutableMap()

    // Update to the most recent error if it's not null, otherwise keep the old one
    val error = this.error ?: prevTriggerRunResult.error

    return this.copy(aggregationResultBuckets = mergedAggregationResultBuckets, actionResultsMap = mergedActionResultsMap, error = error)
}

fun defaultToPerExecutionAction(
    maxActionableAlertCount: Long,
    monitorId: String,
    triggerId: String,
    totalActionableAlertCount: Int,
    monitorOrTriggerError: Exception?
): Boolean {
    // If the monitorId or triggerResult has an error, then also default to PER_EXECUTION to communicate the error
    if (monitorOrTriggerError != null) {
        logger.debug(
            "Trigger [$triggerId] in monitor [$monitorId] encountered an error. Defaulting to " +
                "[${ActionExecutionScope.Type.PER_EXECUTION}] for action execution to communicate error."
        )
        return true
    }

    // If the MAX_ACTIONABLE_ALERT_COUNT is set to -1, consider it unbounded and proceed regardless of actionable Alert count
    if (maxActionableAlertCount < 0) return false

    // If the total number of Alerts to execute Actions on exceeds the MAX_ACTIONABLE_ALERT_COUNT setting then default to
    // PER_EXECUTION for less intrusive Actions
    if (totalActionableAlertCount > maxActionableAlertCount) {
        logger.debug(
            "The total actionable alerts for trigger [$triggerId] in monitor [$monitorId] is [$totalActionableAlertCount] " +
                "which exceeds the maximum of [$maxActionableAlertCount]. " +
                "Defaulting to [${ActionExecutionScope.Type.PER_EXECUTION}] for action execution."
        )
        return true
    }

    return false
}

/**
 * Executes the given [block] function on this resource and then closes it down correctly whether an exception
 * is thrown or not.
 *
 * In case if the resource is being closed due to an exception occurred in [block], and the closing also fails with an exception,
 * the latter is added to the [suppressed][java.lang.Throwable.addSuppressed] exceptions of the former.
 *
 * @param block a function to process this [AutoCloseable] resource.
 * @return the result of [block] function invoked on this resource.
 */
inline fun <T : ThreadContext.StoredContext, R> T.use(block: (T) -> R): R {
    var exception: Throwable? = null
    try {
        return block(this)
    } catch (e: Throwable) {
        exception = e
        throw e
    } finally {
        closeFinally(exception)
    }
}

fun getCancelAfterTimeInterval(): Long {
    // The default value for the cancelAfterTimeInterval is -1 and so, in this case
    // we should ignore processing on the value
    val givenInterval = MonitorRunnerService.monitorCtx.cancelAfterTimeInterval!!.minutes
    if (givenInterval == -1L) {
        return givenInterval
    }
    return max(givenInterval, AlertService.ALERTS_SEARCH_TIMEOUT.minutes)
}

/**
 * Closes this [AutoCloseable], suppressing possible exception or error thrown by [AutoCloseable.close] function when
 * it's being closed due to some other [cause] exception occurred.
 *
 * The suppressed exception is added to the list of suppressed exceptions of [cause] exception.
 */
fun ThreadContext.StoredContext.closeFinally(cause: Throwable?) = when (cause) {
    null -> close()
    else -> try {
        close()
    } catch (closeException: Throwable) {
        cause.addSuppressed(closeException)
    }
}

/**
 * Mustache template supports iterating through a list using a `{{#listVariable}}{{/listVariable}}` block.
 * https://mustache.github.io/mustache.5.html
 *
 * This function looks for `{{#${[AlertContext.SAMPLE_DOCS_FIELD]}}}{{/${[AlertContext.SAMPLE_DOCS_FIELD]}}}` blocks,
 * and parses the contents for tags, which we interpret as fields within the sample document.
 *
 * @return a [Set] of [String]s indicating fields within a document.
 */
fun parseSampleDocTags(messageTemplate: Script): Set<String> {
    val sampleBlockPrefix = "{{#${AlertContext.SAMPLE_DOCS_FIELD}}}"
    val sampleBlockSuffix = "{{/${AlertContext.SAMPLE_DOCS_FIELD}}}"
    val sourcePrefix = "_source."
    val tagRegex = Regex("\\{\\{([^{}]+)}}")
    val tags = mutableSetOf<String>()
    try {
        // Identify the start and end points of the sample block
        var blockStart = messageTemplate.idOrCode.indexOf(sampleBlockPrefix)
        var blockEnd = messageTemplate.idOrCode.indexOf(sampleBlockSuffix, blockStart)

        // Sample start/end of -1 indicates there are no more complete sample blocks
        while (blockStart != -1 && blockEnd != -1) {
            // Isolate the sample block
            val sampleBlock = messageTemplate.idOrCode.substring(blockStart, blockEnd)
                // Remove the iteration wrapper tags
                .removePrefix(sampleBlockPrefix)
                .removeSuffix(sampleBlockSuffix)

            // Search for each tag
            tagRegex.findAll(sampleBlock).forEach { match ->
                // Parse the field name from the tag (e.g., `{{_source.timestamp}}` becomes `timestamp`)
                var docField = match.groupValues[1].trim()
                if (docField.startsWith(sourcePrefix)) {
                    docField = docField.removePrefix(sourcePrefix)
                    if (docField.isNotEmpty()) tags.add(docField)
                }
            }

            // Identify any subsequent sample blocks
            blockStart = messageTemplate.idOrCode.indexOf(sampleBlockPrefix, blockEnd)
            blockEnd = messageTemplate.idOrCode.indexOf(sampleBlockSuffix, blockStart)
        }
    } catch (e: Exception) {
        logger.warn("Failed to parse sample document fields.", e)
    }
    return tags
}

fun parseSampleDocTags(triggers: List<Trigger>): Set<String> {
    return triggers.flatMap { trigger ->
        trigger.actions.flatMap { action -> parseSampleDocTags(action.messageTemplate) }
    }.toSet()
}

/**
 * Checks the `message_template.source` in the [Script] for each [Action] in the [Trigger] for
 * any instances of [AlertContext.SAMPLE_DOCS_FIELD] tags.
 * This indicates the message is expected to print data from the sample docs, so we need to collect the samples.
 */
fun printsSampleDocData(trigger: Trigger): Boolean {
    return trigger.actions.any { action ->
        val alertsField = when (trigger) {
            is BucketLevelTrigger -> "{{ctx.${BucketLevelTriggerExecutionContext.NEW_ALERTS_FIELD}}}"
            is DocumentLevelTrigger -> "{{ctx.${DocumentLevelTriggerExecutionContext.ALERTS_FIELD}}}"
            // Only bucket, and document level monitors are supported currently.
            else -> return false
        }

        // TODO: Consider excluding the following tags from TRUE criteria (especially for bucket-level triggers) as
        //  printing all of the sample documents could make the notification message too large to send.
        //  1. {{ctx}} - prints entire ctx object in the message string
        //  2. {{ctx.<alertsField>}} - prints entire alerts array in the message string, which includes the sample docs
        //  3. {{AlertContext.SAMPLE_DOCS_FIELD}} - prints entire sample docs array in the message string
        val validTags = listOfNotNull(
            "{{ctx}}",
            alertsField,
            AlertContext.SAMPLE_DOCS_FIELD
        )
        validTags.any { tag -> action.messageTemplate.idOrCode.contains(tag) }
    }
}

/**
 * Class names recorded by `AlertingException.wrap()` when it flattens a cause into
 * `Exception("<class name>: <message>")`. The original exception type does not survive that
 * flattening, so for a caller above the first conversion the recorded name is the only signal left.
 */
private val NODE_UNAVAILABLE_EXCEPTION_NAMES = setOf(
    NodeClosedException::class.java.name,
    NodeNotConnectedException::class.java.name
)

/** Guards against a self-referencing or pathologically deep cause chain. */
private const val MAX_CAUSE_CHAIN_DEPTH = 10

/**
 * Returns true when [e], or any cause it wraps, means the local node is shutting down or a peer has
 * gone away, rather than a genuine failure of the operation being attempted.
 *
 * Such a failure is a normal outcome of a restart: the run is abandoned and retried on the next
 * schedule, so it does not warrant error-level logging.
 *
 * The whole chain is walked rather than just `ExceptionsHelper.unwrapCause()`, because
 * `AlertingException` is not an `OpenSearchWrapperException` -- unwrapping stops at it -- and it
 * flattens its cause, so a shutdown that has already been converted once is only recognisable by
 * the class name that conversion recorded.
 */
fun isNodeUnavailableFailure(e: Exception): Boolean {
    var cause: Throwable? = e
    var depth = 0
    while (cause != null && depth++ < MAX_CAUSE_CHAIN_DEPTH) {
        if (cause is NodeClosedException || cause is NodeNotConnectedException) {
            return true
        }
        val message = cause.message
        if (message != null && NODE_UNAVAILABLE_EXCEPTION_NAMES.any { message.startsWith("$it:") }) {
            return true
        }
        val next = cause.cause
        cause = if (next === cause) null else next
    }
    return false
}

/**
 * Class names recorded by `AlertingException.wrap()` for the resource-pressure failures below, for the
 * same reason [NODE_UNAVAILABLE_EXCEPTION_NAMES] exists: the original type does not survive flattening.
 */
private val RESOURCE_PRESSURE_EXCEPTION_NAMES = setOf(
    TaskCancelledException::class.java.name,
    CircuitBreakingException::class.java.name,
    OpenSearchRejectedExecutionException::class.java.name
)

/**
 * The deepest cause of [e] rendered as `SimpleName: message`.
 *
 * Lets a failure be reported on one line, naming the real reason without attaching a stack trace. For a
 * search cancelled by backpressure this reaches the `TaskCancelledException` and its reason, because
 * `SearchPhaseExecutionException` wires its first shard failure's cause into its own cause chain.
 */
fun rootCauseMessage(e: Throwable): String {
    var cause: Throwable = e
    var depth = 0
    while (depth++ < MAX_CAUSE_CHAIN_DEPTH) {
        val next = cause.cause ?: break
        if (next === cause) break
        cause = next
    }
    return "${cause.javaClass.simpleName}: ${cause.message}"
}

/**
 * Returns true when [e], or any cause it wraps, means the cluster refused to finish the work because it
 * was short of resources -- `SearchBackpressureService` cancelling the task in enforced mode, a tripped
 * circuit breaker, or a rejected execution -- rather than a defect in the request itself.
 *
 * Such a failure says nothing about whether the work is valid, only that there was no headroom for it at
 * that size. The caller can therefore retry it in smaller pieces, or leave it for the next run, instead
 * of discarding it.
 *
 * A cancelled search reaches the client as a `SearchPhaseExecutionException` ("all shards failed") whose
 * per-shard causes carry the real reason. Only the *first* shard failure is wired into the exception's own
 * cause chain, so every shard failure is inspected too: the cancelled shard need not be the first one.
 */
fun isResourcePressureFailure(e: Throwable): Boolean {
    var cause: Throwable? = e
    var depth = 0
    while (cause != null && depth++ < MAX_CAUSE_CHAIN_DEPTH) {
        if (cause is TaskCancelledException ||
            cause is CircuitBreakingException ||
            cause is OpenSearchRejectedExecutionException
        ) {
            return true
        }
        val message = cause.message
        if (message != null && RESOURCE_PRESSURE_EXCEPTION_NAMES.any { message.startsWith("$it:") }) {
            return true
        }
        val current = cause
        if (current is SearchPhaseExecutionException &&
            current.shardFailures().any { failure -> failure.cause?.let { isResourcePressureFailure(it) } == true }
        ) {
            return true
        }
        val next = cause.cause
        cause = if (next === cause) null else next
    }
    return false
}
