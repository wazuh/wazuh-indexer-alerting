/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.opensearchapi

import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.Logger
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.atLeastOnce
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.opensearch.OpenSearchStatusException
import org.opensearch.action.bulk.BackoffPolicy
import org.opensearch.common.unit.TimeValue
import org.opensearch.core.rest.RestStatus
import org.opensearch.test.OpenSearchTestCase

class OpenSearchExtensionsTests : OpenSearchTestCase() {

    private fun backoffPolicy() = BackoffPolicy.constantBackoff(TimeValue.timeValueMillis(1), 2)

    fun `test retry does not log the stack trace when disabled`() {
        val logger = mock(Logger::class.java)
        var attempts = 0

        val result = runBlocking {
            backoffPolicy().retry(logger, emptyList(), logRetryStackTrace = false) {
                attempts++
                if (attempts < 2) throw OpenSearchStatusException("boom", RestStatus.SERVICE_UNAVAILABLE)
                "ok"
            }
        }

        assertEquals("ok", result)
        assertEquals(2, attempts)
        // The intermediate failure must be reported as a single line, never as a warn carrying the throwable.
        verify(logger, never()).warn(anyString(), any(Throwable::class.java))
    }

    fun `test retry keeps logging the stack trace by default`() {
        val logger = mock(Logger::class.java)
        var attempts = 0

        val result = runBlocking {
            backoffPolicy().retry(logger) {
                attempts++
                if (attempts < 2) throw OpenSearchStatusException("boom", RestStatus.SERVICE_UNAVAILABLE)
                "ok"
            }
        }

        assertEquals("ok", result)
        assertEquals(2, attempts)
        // Callers that did not opt out keep the previous behaviour.
        verify(logger, atLeastOnce()).warn(anyString(), any(Throwable::class.java))
    }
}
