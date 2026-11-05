/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.mockito.Mockito.mock
import org.opensearch.alerting.util.DocLevelMonitorQueries.Companion.ABSENT_FIELD_SENTINEL
import org.opensearch.cluster.service.ClusterService
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.transport.client.Client

class DocLevelMonitorQueriesTests : OpenSearchTestCase() {

    private val docLevelMonitorQueries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))

    fun `test transformAbsentFieldQuery rewrites exists clauses over an unmapped field`() {
        val query = "(event.action_idx_mid: \"logged-in\") AND (NOT _exists_: user.name)"

        val transformed = docLevelMonitorQueries.transformAbsentFieldQuery(query, listOf("user.name"))

        assertEquals(
            "(event.action_idx_mid: \"logged-in\") AND (NOT _exists_:$ABSENT_FIELD_SENTINEL)",
            transformed
        )
    }

    fun `test transformAbsentFieldQuery rewrites value clauses over an unmapped field`() {
        val query = "(user.name: \"admin\") AND (NOT user.id: * AND _exists_:user.id)"

        val transformed = docLevelMonitorQueries.transformAbsentFieldQuery(query, listOf("user.name", "user.id"))

        assertEquals(
            "($ABSENT_FIELD_SENTINEL: \"admin\") AND (NOT $ABSENT_FIELD_SENTINEL: * AND _exists_:$ABSENT_FIELD_SENTINEL)",
            transformed
        )
    }

    fun `test transformAbsentFieldQuery leaves mapped fields and partial name matches untouched`() {
        val query = "(user.name_idx_mid: \"admin\") AND (host.user.name: \"root\") AND (name: \"x\") AND (message: \"user.name\")"

        val transformed = docLevelMonitorQueries.transformAbsentFieldQuery(query, listOf("user.name"))

        assertEquals(query, transformed)
    }

    fun `test transformAbsentFieldQuery is a no-op without absent fields`() {
        val query = "(event.action_idx_mid: \"logged-in\") AND (_exists_:user.name_idx_mid)"

        assertEquals(query, docLevelMonitorQueries.transformAbsentFieldQuery(query, emptyList()))
    }

    fun `test fieldNamesIn reads value and exists clauses`() {
        val query = "(event.kind: \"event\") AND (NOT _exists_: user.name) AND (NOT process.title: \"nope\")"

        assertEquals(setOf("event.kind", "user.name", "process.title"), docLevelMonitorQueries.fieldNamesIn(query))
    }

    fun `test fieldNamesIn finds no field in a keyword term`() {
        assertEquals(emptySet<String>(), docLevelMonitorQueries.fieldNamesIn("\"DataError\" OR *Timeout*"))
    }

    fun `test fieldNamesIn skips colons inside quoted values, regular expressions and escapes`() {
        val query = "(url.full: \"http://host:8080/a\") AND (file.path: /C:\\\\.*/) AND (message: a\\:b) AND \"k:v\""

        assertEquals(setOf("url.full", "file.path", "message"), docLevelMonitorQueries.fieldNamesIn(query))
    }

    fun `test a query without field names gets its unmapped fields rewritten`() {
        // A rule matching a keyword in any field and a field condition: `keywords and not f`.
        val query = "(\"QVLT1747MIX\") AND (NOT process.title: \"nope\")"

        val transformed = docLevelMonitorQueries.transformAbsentFieldQuery(query, docLevelMonitorQueries.fieldNamesIn(query))

        assertEquals("(\"QVLT1747MIX\") AND (NOT $ABSENT_FIELD_SENTINEL: \"nope\")", transformed)
    }
}
