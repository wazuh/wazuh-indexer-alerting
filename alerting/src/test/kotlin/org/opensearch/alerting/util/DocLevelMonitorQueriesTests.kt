/*
 * Copyright (C) 2026, Wazuh Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LogEvent
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doAnswer
import org.mockito.Mockito.mock
import org.opensearch.Version
import org.opensearch.action.DocWriteRequest
import org.opensearch.action.bulk.BulkItemResponse
import org.opensearch.action.bulk.BulkRequest
import org.opensearch.action.bulk.BulkResponse
import org.opensearch.action.index.IndexRequest
import org.opensearch.action.support.WriteRequest.RefreshPolicy
import org.opensearch.alerting.util.DocLevelMonitorQueries.Companion.ABSENT_FIELD_SENTINEL
import org.opensearch.cluster.ClusterName
import org.opensearch.cluster.ClusterState
import org.opensearch.cluster.metadata.IndexMetadata
import org.opensearch.cluster.metadata.Metadata
import org.opensearch.cluster.routing.RoutingTable
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.unit.TimeValue
import org.opensearch.common.xcontent.XContentHelper
import org.opensearch.common.xcontent.json.JsonXContent
import org.opensearch.commons.alerting.model.DocLevelQuery
import org.opensearch.core.action.ActionListener
import org.opensearch.core.index.Index
import org.opensearch.index.mapper.MapperParsingException
import org.opensearch.index.query.QueryShardException
import org.opensearch.test.MockLogAppender
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

    fun `test doIndexAllQueries rewrites the unmapped fields of a query without field names`() {
        // `keywords and not f`, with `f` on the unmapped `process.title`: Security Analytics sends no field names.
        val mixed = DocLevelQuery("mixed", "mixed", emptyList(), "(\"QVLT1747MIX\") AND (NOT process.title: \"nope\")", emptyList(), emptyList())
        // The same clause on a mapped field is renamed as before.
        val mapped = DocLevelQuery("mapped", "mapped", emptyList(), "(\"QVLT1747MIX\") AND (NOT message: \"nope\")", emptyList(), emptyList())
        // A query that carries field names is rewritten from those only.
        val named = DocLevelQuery("named", "named", emptyList(), "(NOT process.title: \"nope\")", emptyList(), listOf("event.kind"))

        val indexed = indexAllQueries(listOf(mixed, mapped, named), mutableSetOf(Pair("message", "idx")))

        assertEquals(
            mapOf(
                "mixed_idx_mid" to "(\"QVLT1747MIX\") AND (NOT $ABSENT_FIELD_SENTINEL: \"nope\")",
                "mapped_idx_mid" to "(\"QVLT1747MIX\") AND (NOT message_idx_mid: \"nope\")",
                "named_idx_mid" to "(NOT process.title: \"nope\")"
            ),
            indexed
        )
    }

    fun `test doIndexAllQueries leaves metadata fields alone`() {
        // Metadata fields are never mapped, but every document has them.
        val id = DocLevelQuery("id", "id", emptyList(), "_id:*", emptyList(), emptyList())
        val namedId = DocLevelQuery("named-id", "named-id", emptyList(), "_id:*", emptyList(), listOf("_id"))
        val index = DocLevelQuery("index", "index", emptyList(), "_index:idx AND message:\"a\"", emptyList(), emptyList())

        val indexed = indexAllQueries(listOf(id, namedId, index), mutableSetOf(Pair("message", "idx")))

        assertEquals(
            mapOf(
                "id_idx_mid" to "_id:*",
                "named-id_idx_mid" to "_id:*",
                "index_idx_mid" to "_index:idx AND message_idx_mid:\"a\""
            ),
            indexed
        )
    }

    fun `test sourceProperties adds the leaf a dynamic template declares for an unmapped field`() {
        val properties = docLevelMonitorQueries.sourceProperties(
            mapping(STREAM_MAPPING), listOf("registry.path", "source.ip", "source.bytes", "host.cpu.usage", "process.pid")
        )

        // Each leaf is the mapping of its template, type and parameters, under the objects the index declares or lacks.
        val expected = mapping(
            """
            {
              "registry": {"properties": {"path": {"type": "keyword", "ignore_above": 4096}}},
              "source": {"properties": {"port": {"type": "long"}, "ip": {"type": "ip"}, "bytes": {"type": "long"}}},
              "host": {"properties": {"cpu": {"properties": {"usage": {"type": "scaled_float", "scaling_factor": 1000}}}}},
              "process": {"properties": {"pid": {"type": "long"}}}
            }
            """
        )
        assertEquals(expected, properties)
    }

    fun `test sourceProperties leaves mapped fields, undeclared fields and fields no query names as they are`() {
        val mapping = mapping(STREAM_MAPPING)

        // `source.port` is mapped, no template declares `registry.value`, and nothing names the declared `source.ip`.
        val properties = docLevelMonitorQueries.sourceProperties(mapping, listOf("source.port", "registry.value", "source"))

        assertEquals(mapping(STREAM_MAPPING)["properties"], properties)
        assertSame(mapping["properties"], docLevelMonitorQueries.sourceProperties(mapping, emptyList()))
    }

    fun `test sourceProperties declares nothing where the index cannot map the field`() {
        val template = """{"a_b": {"path_match": "a.b", "mapping": {"type": "keyword"}}}"""
        listOf(
            // New fields are refused or ignored, with or without templates.
            """{"dynamic": "strict", "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": "false", "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": false, "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            // The object sets it for its own fields.
            """{"dynamic_templates": [$template], "properties": {"a": {"dynamic": "strict", "properties": {"c": {"type": "long"}}}}}""",
            // The parent is a field, a nested object or a disabled object.
            """{"dynamic_templates": [$template], "properties": {"a": {"type": "keyword"}}}""",
            """{"dynamic_templates": [$template], "properties": {"a": {"type": "nested"}}}""",
            """{"dynamic_templates": [$template], "properties": {"a": {"type": "object", "enabled": false}}}"""
        ).forEach { json ->
            assertEquals(json, mapping(json)["properties"], docLevelMonitorQueries.sourceProperties(mapping(json), listOf("a.b")))
        }
    }

    fun `test sourceProperties declares fields wherever dynamic templates apply`() {
        val template = """{"a_b": {"path_match": "a.b", "mapping": {"type": "keyword"}}}"""
        val declared = mapping("""{"a": {"properties": {"b": {"type": "keyword"}}}}""")
        listOf(
            """{"dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": "true", "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": true, "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": "false_allow_templates", "dynamic_templates": [$template], "properties": {"a": {"type": "object"}}}""",
            """{"dynamic": "strict", "dynamic_templates": [$template], "properties": {"a": {"dynamic": "strict_allow_templates"}}}""",
            // An index with templates and no field yet.
            """{"dynamic": "strict_allow_templates", "dynamic_templates": [$template]}"""
        ).forEach { json ->
            val properties = docLevelMonitorQueries.sourceProperties(mapping(json), listOf("a.b"))!!
            // The object keeps its own settings: only its fields are compared.
            @Suppress("UNCHECKED_CAST")
            val fields = (properties["a"] as Map<String, Any>).filterKeys { it == "properties" }
            assertEquals(json, declared["a"], fields)
        }
    }

    fun `test sourceProperties is null for an index with no field, mapped or declared`() {
        val template = """{"a_b": {"path_match": "a.b", "mapping": {"type": "keyword"}}}"""

        assertNull(docLevelMonitorQueries.sourceProperties(null, listOf("a.b")))
        assertNull(docLevelMonitorQueries.sourceProperties(mapping("""{"dynamic": "true"}"""), listOf("a.b")))
        assertNull(docLevelMonitorQueries.sourceProperties(mapping("""{"dynamic_templates": [$template]}"""), listOf("c.d")))
        // A name that is not a field path is never declared, whatever the template matches.
        val any = """{"any": {"path_match": "*", "mapping": {"type": "keyword"}}}"""
        assertNull(docLevelMonitorQueries.sourceProperties(mapping("""{"dynamic_templates": [$any]}"""), listOf("", "a.", ".b", "a..b")))
    }

    fun `test the traversal visits a field declared under an object that had no fields`() {
        // An object with no fields is rendered as {"type": "object"}, which the traversal takes for a leaf.
        val properties = docLevelMonitorQueries.sourceProperties(mapping(STREAM_MAPPING), listOf("registry.path", "host.cpu.usage"))!!
        val flattenPaths = mutableMapOf<String, MutableMap<String, Any>>()
        val renamed = fun(name: String, _: String, props: MutableMap<String, Any>) = Triple(name, "${name}_idx_mid", props)

        docLevelMonitorQueries.traverseMappingsAndUpdate(properties, "", renamed, flattenPaths)

        assertEquals(setOf("registry.path", "host.cpu.usage", "source.port"), flattenPaths.keys)
        assertEquals(mapping("""{"properties": {"path_idx_mid": {"type": "keyword", "ignore_above": 4096}}}"""), properties["registry"])
    }

    fun `test declaredLeaf takes the first template that matches the field`() {
        val templates = templates(
            """{"path_match": "user.id", "mapping": {"type": "long"}}""",
            // `*` crosses the dots of a path, as it does when a document is indexed.
            """{"path_match": "user.*", "mapping": {"type": "ip"}}""",
            """{"path_match": "user.id", "mapping": {"type": "keyword"}}""",
            """{"match": "*_at", "unmatch": "deleted_*", "path_unmatch": "internal.*", "mapping": {"type": "date"}}""",
            """{"match_pattern": "regex", "path_match": "^labels\\.[a-z]+$", "mapping": {"type": "boolean"}}"""
        )

        assertEquals(mapOf("type" to "long"), docLevelMonitorQueries.declaredLeaf("user.id", templates))
        assertEquals(mapOf("type" to "ip"), docLevelMonitorQueries.declaredLeaf("user.address.public", templates))
        assertEquals(mapOf("type" to "date"), docLevelMonitorQueries.declaredLeaf("event.created_at", templates))
        assertEquals(mapOf("type" to "boolean"), docLevelMonitorQueries.declaredLeaf("labels.trusted", templates))
        // Refused by `unmatch`, by `path_unmatch`, by the regular expression, or matched by no template.
        assertNull(docLevelMonitorQueries.declaredLeaf("event.deleted_at", templates))
        assertNull(docLevelMonitorQueries.declaredLeaf("internal.created_at", templates))
        assertNull(docLevelMonitorQueries.declaredLeaf("labels.Trusted", templates))
        assertNull(docLevelMonitorQueries.declaredLeaf("user", templates))
        // An index can carry a regular expression that does not compile: nothing is assumed from it.
        val broken = templates("""{"match_pattern": "regex", "path_match": "user.(", "mapping": {"type": "keyword"}}""", """{"path_match": "user.id", "mapping": {"type": "long"}}""")
        assertNull(docLevelMonitorQueries.declaredLeaf("user.id", broken))
    }

    fun `test declaredLeaf gives no mapping when the first match cannot tell it before a document`() {
        val known = """{"path_match": "user.id", "mapping": {"type": "long"}}"""
        listOf(
            // The template applies to some values only.
            """{"path_match": "user.*", "match_mapping_type": "string", "mapping": {"type": "keyword"}}""",
            // The mapping is filled from the document, also with the older spelling of the type placeholder.
            """{"path_match": "user.*", "mapping": {"type": "{dynamic_type}"}}""",
            """{"path_match": "user.*", "mapping": {"type": "{dynamicType}"}}""",
            """{"path_match": "user.*", "mapping": {"type": "text", "copy_to": "all_{name}"}}""",
            """{"path_match": "user.*", "mapping": {"ignore_above": 1024}}""",
            // The field is an object.
            """{"path_match": "user.*", "mapping": {"type": "object"}}""",
            """{"path_match": "user.*", "mapping": {"type": "nested"}}"""
        ).forEach { undecided ->
            // The later template is not tried: when a document arrives, the first match is the one applied.
            assertNull(undecided, docLevelMonitorQueries.declaredLeaf("user.id", templates(undecided, known)))
            assertEquals(mapOf("type" to "long"), docLevelMonitorQueries.declaredLeaf("user.id", templates(known, undecided)))
        }
    }

    fun `test a field one index maps and another declares the same way is not a conflict`() {
        val mapped = """{"properties": {"registry": {"properties": {"path": {"type": "keyword", "ignore_above": 4096}}}}}"""
        val state = clusterState("events-000001" to mapped, "events-000002" to STREAM_MAPPING)
        val queries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))

        assertEquals(
            emptySet<String>(),
            queries.getAllConflictingFields(state, listOf("events-000001", "events-000002"), listOf(REGISTRY_QUERY))
        )
    }

    fun `test a field one index maps and another declares with another type is a conflict`() {
        val mapped = """{"properties": {"registry": {"properties": {"path": {"type": "text"}}}}}"""
        val state = clusterState("events-000001" to mapped, "events-000002" to STREAM_MAPPING)
        val queries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))

        assertEquals(
            setOf("registry.path"),
            queries.getAllConflictingFields(state, listOf("events-000001", "events-000002"), listOf(REGISTRY_QUERY))
        )
        // Only the fields the queries name are read from the templates, and one index alone has no conflict.
        assertEquals(emptySet<String>(), queries.getAllConflictingFields(state, listOf("events-000001", "events-000002"), emptyList()))
        assertEquals(emptySet<String>(), queries.getAllConflictingFields(state, listOf("events-000002"), listOf(REGISTRY_QUERY)))
    }

    fun `test a number written as an integer in a template and stored as a decimal is not a conflict`() {
        // A mapped scaled_float gives its scaling factor back as 1000.0; the template says 1000.
        val mapped = """{"properties": {"host": {"properties": {"cpu": {"properties": {"usage": {"type": "scaled_float", "scaling_factor": 1000.0}}}}}}}"""
        val other = """{"properties": {"host": {"properties": {"cpu": {"properties": {"usage": {"type": "scaled_float", "scaling_factor": 100.0}}}}}}}"""
        val queries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))
        val indices = listOf("events-000001", "events-000002")

        val usage = listOf(DocLevelQuery("usage", "usage", emptyList(), "host.cpu.usage:>0.9", emptyList(), listOf("host.cpu.usage")))

        val same = queries.getAllConflictingFields(clusterState("events-000001" to mapped, "events-000002" to STREAM_MAPPING), indices, usage)
        val different = queries.getAllConflictingFields(clusterState("events-000001" to other, "events-000002" to STREAM_MAPPING), indices, usage)

        assertEquals(emptySet<String>(), same)
        assertEquals(setOf("host.cpu.usage"), different)
    }

    fun `test the queries over undeclared fields are reported once while they are the same`() {
        val queries = DocLevelMonitorQueries(mock(Client::class.java), mock(ClusterService::class.java))
        val mapped = setOf("event.kind")
        val declared = DocLevelQuery("declared", "declared", emptyList(), "event.kind:\"event\" AND _id:*", emptyList(), emptyList())
        // Security Analytics gives every query the field names of all the rules of the detector.
        val shared = listOf("user.id", "event.kind", "labels.env", "user.name")
        val named = DocLevelQuery("named", "named", emptyList(), "user.id:1 AND event.kind:\"a\"", emptyList(), shared)
        val other = DocLevelQuery("other", "other", emptyList(), "event.kind:\"b\"", emptyList(), shared)
        val unnamed = DocLevelQuery("unnamed", "unnamed", emptyList(), "NOT _exists_:user.name AND labels.env:\"x\"", emptyList(), emptyList())

        val first = queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, named, other, unnamed), mapped)

        assertEquals(
            "Monitor mid: 2 of its 4 queries name fields that [events*] neither maps nor declares in a dynamic template. " +
                "Their clauses over those fields match no document until it does: named [user.id]; unnamed [labels.env, user.name]",
            first
        )
        // The same queries on the next runs, and on another source index of the monitor.
        assertNull(queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, named, other, unnamed), mapped))
        assertNotNull(queries.undeclaredFieldsMessage("mid", "other", "other", listOf(declared, named, other, unnamed), mapped))
        // A field got mapped: the set changed.
        val second = queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, named, other, unnamed), mapped + "user.id")
        assertTrue(second, second!!.contains("1 of its 4 queries") && second.endsWith(": unnamed [labels.env, user.name]"))
        // Nothing left to report, and nothing reported when the same queries come back after that.
        assertNull(queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared), mapped))
        assertNotNull(queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, unnamed), mapped))
        // An updated or deleted monitor is forgotten.
        assertNull(queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, unnamed), mapped))
        queries.forgetIndexedQueries("mid")
        assertNotNull(queries.undeclaredFieldsMessage("mid", "events*", "events_", listOf(declared, unnamed), mapped))
    }

    fun `test queries the query index refuses for an unmapped field are logged once while they are the same`() {
        // `registry.value` is missing from the field names, so it is neither renamed nor pointed at the sentinel.
        val named = DocLevelQuery("named", "named", emptyList(), "registry.path:\"a\" AND registry.value:\"b\"", emptyList(), listOf("registry.path"))
        val other = DocLevelQuery("other", "other", emptyList(), "registry.path:\"c\"", emptyList(), listOf("registry.path"))
        val client = mock(Client::class.java)
        // The field the query index refuses in the next bulk, by query document id.
        var refusedFields = emptyMap<String, String>()
        doAnswer { invocation ->
            val requests = invocation.getArgument<BulkRequest>(0).requests()
            val items = requests.mapIndexedNotNull { i, request ->
                refusedFields[request.id()]?.let { field ->
                    val reason = QueryShardException(Index("query-index", "_na_"), "No field mapping can be found for the field with name [{}]", null, field)
                    val cause = MapperParsingException("failed to parse field [query] of type [percolator]", reason)
                    BulkItemResponse(i, DocWriteRequest.OpType.INDEX, BulkItemResponse.Failure("query-index", request.id(), cause))
                }
            }
            invocation.getArgument<ActionListener<BulkResponse>>(1).onResponse(BulkResponse(items.toTypedArray(), 0))
            null
        }.`when`(client).bulk(any(), any())
        val queries = DocLevelMonitorQueries(client, mock(ClusterService::class.java))

        /** Indexes both queries over source index `idx`, refusing [refused], and gives the WARN lines logged. */
        fun warnings(refused: Map<String, String>): List<String> {
            refusedFields = refused
            val logged = mutableListOf<String>()
            MockLogAppender.createForLoggers(LogManager.getLogger(DocLevelMonitorQueries::class.java)).use { appender ->
                appender.addExpectation(object : MockLogAppender.LoggingExpectation {
                    override fun match(event: LogEvent) {
                        if (event.level == Level.WARN) logged.add(event.message.formattedMessage)
                    }

                    override fun assertMatched() {}
                })
                runBlocking {
                    queries.doIndexAllQueries(
                        "query-index", "idx", "mid", listOf(named, other), mutableSetOf(Pair("registry.path", "idx")), emptySet(),
                        RefreshPolicy.NONE, TimeValue.timeValueSeconds(1)
                    )
                }
            }
            return logged
        }

        val refusedNamed = mapOf("named_idx_mid" to "registry.value")
        assertEquals(
            listOf(
                "Monitor mid: the query index refused 1 of its 2 queries over [idx], which name a field it has no mapping for. " +
                    "They match no document: named [registry.value]"
            ),
            warnings(refusedNamed)
        )
        // The next runs index the queries again, and the query index refuses the same one.
        assertEquals(emptyList<String>(), warnings(refusedNamed))
        // Once nothing is refused, a refusal is new again.
        assertEquals(emptyList<String>(), warnings(emptyMap()))
        assertEquals(1, warnings(refusedNamed).size)
        // Another set of refused queries.
        val both = warnings(refusedNamed + ("other_idx_mid" to "registry.path"))
        assertEquals(both.toString(), 1, both.size)
        val bothRefused = "refused 2 of its 2 queries over [idx], which name a field it has no mapping for. " +
            "They match no document: named [registry.value]; other [registry.path]"
        assertTrue(both.single(), both.single().endsWith(bothRefused))
        // An updated or deleted monitor is forgotten.
        queries.forgetIndexedQueries("mid")
        assertEquals(1, warnings(refusedNamed).size)
    }

    /** The parsed form of a mapping, as an index gives it. */
    private fun mapping(json: String): MutableMap<String, Any> = XContentHelper.convertToMap(JsonXContent.jsonXContent, json, false)

    /** Dynamic templates with the given bodies, named t0, t1... */
    private fun templates(vararg bodies: String): List<*> =
        mapping("""{"dynamic_templates": [${bodies.mapIndexed { i, body -> """{"t$i": $body}""" }.joinToString()}]}""")["dynamic_templates"] as List<*>

    /** A cluster state with the given indices and their mappings. */
    private fun clusterState(vararg indices: Pair<String, String>): ClusterState {
        val metadata = Metadata.builder()
        val routingTable = RoutingTable.builder()
        indices.forEach { (name, mapping) ->
            val index = IndexMetadata.builder(name).settings(settings(Version.CURRENT)).numberOfShards(1).numberOfReplicas(0)
                .putMapping(mapping).build()
            metadata.put(index, false)
            routingTable.addAsNew(index)
        }
        return ClusterState.builder(ClusterName("test")).metadata(metadata).routingTable(routingTable.build()).build()
    }

    /** Runs doIndexAllQueries over source index `idx` and monitor `mid`, and gives the query indexed for each id. */
    private fun indexAllQueries(queries: List<DocLevelQuery>, flattenPaths: MutableSet<Pair<String, String>>): Map<String, String> {
        val client = mock(Client::class.java)
        val requests = mutableListOf<BulkRequest>()
        doAnswer { invocation ->
            requests.add(invocation.getArgument(0))
            invocation.getArgument<ActionListener<BulkResponse>>(1).onResponse(BulkResponse(arrayOf<BulkItemResponse>(), 0))
            null
        }.`when`(client).bulk(any(), any())

        runBlocking {
            DocLevelMonitorQueries(client, mock(ClusterService::class.java)).doIndexAllQueries(
                "query-index", "idx", "mid", queries, flattenPaths, emptySet(), RefreshPolicy.NONE, TimeValue.timeValueSeconds(1)
            )
        }

        return requests.single().requests().associate { request ->
            @Suppress("UNCHECKED_CAST")
            val queryString = ((request as IndexRequest).sourceAsMap()["query"] as Map<String, Map<String, Any>>)["query_string"]!!
            request.id() to queryString["query"] as String
        }
    }

    companion object {
        /** A query that names its field in its text only. */
        private val REGISTRY_QUERY = DocLevelQuery("registry", "registry", emptyList(), "registry.path:\"HKLM\"", emptyList(), emptyList())

        /**
         * The mapping of an events stream before any document: `strict_allow_templates`, one dynamic template per
         * field, the objects declared with no fields, and one field already mapped.
         */
        private const val STREAM_MAPPING = """
            {
              "dynamic": "strict_allow_templates",
              "dynamic_templates": [
                {"registry_path": {"path_match": "registry.path", "mapping": {"type": "keyword", "ignore_above": 4096}}},
                {"source_ip": {"path_match": "source.ip", "mapping": {"type": "ip"}}},
                {"source_bytes": {"path_match": "source.bytes", "mapping": {"type": "long"}}},
                {"host_cpu_usage": {"path_match": "host.cpu.usage", "mapping": {"type": "scaled_float", "scaling_factor": 1000}}},
                {"process_pid": {"path_match": "process.pid", "mapping": {"type": "long"}}}
              ],
              "properties": {
                "registry": {"type": "object"},
                "source": {"properties": {"port": {"type": "long"}}},
                "host": {"properties": {"cpu": {"type": "object"}}}
              }
            }
        """
    }
}
