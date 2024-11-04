package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.repository.exposed.SystemScopes
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.jetbrains.exposed.sql.Table
import org.junit.Before
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.web.ScopeAPI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ScopeTest: ApiTest(ScopeAPI) {

    var scope1Id: Long = -1L
    var scope2Id: Long = -1L

    val nonexistingScopeId: Long get() = maxOf(scope1Id, scope2Id) + 1

    override val deletableTables: List<Table>
        get() = super.deletableTables + listOf(SystemScopes)

    @Before
    override fun setUp() {
        super.setUp()
        scope1Id = testContext.scopeRepository.save(SystemScope(null,"test", "Test Scope Description")).id!!
        scope2Id = testContext.scopeRepository.save(SystemScope(null,"test2", "Other Scope Description")).id!!
    }

    //region Unauthorized accesses
    @Test
    fun testGetAllUnauth() = testEndpoint {
        getUnAuth("/api/scopes", HttpStatusCode.Unauthorized)
    }

     @Test
    fun testGetScopeUnauth() = testEndpoint {
        getUnAuth("/api/scopes/${scope1Id}", HttpStatusCode.Unauthorized)
        getUnAuth("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Unauthorized)
    }

     @Test
    fun testUpdateScopeUnauth() = testEndpoint {
        putUnAuth("/api/scopes/${scope1Id}", HttpStatusCode.Unauthorized)
        putUnAuth("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Unauthorized)
    }

     @Test
    fun testCreateScopeUnauth() = testEndpoint {
        postUnAuth("/api/scopes", HttpStatusCode.Unauthorized)
    }

     @Test
    fun testDeleteScopeUnauth() = testEndpoint {
        deleteUnAuth("/api/scopes/${scope1Id}", HttpStatusCode.Unauthorized)
        deleteUnAuth("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Unauthorized)
    }
    //endregion

    //region Test insufficient authority access
    @Test
    fun testGetAllForbidden() = testEndpoint {
        getUser("/api/scopes", HttpStatusCode.Forbidden)
    }

    @Test
    fun testGetScopeForbidden() = testEndpoint {
        getUser("/api/scopes/${scope1Id}", HttpStatusCode.Forbidden)
        getUser("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Forbidden)
    }

    @Test
    fun testUpdateScopeForbidden() = testEndpoint {
        putClient("/api/scopes/${scope1Id}", HttpStatusCode.Forbidden)
        putClient("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Forbidden)
    }

    @Test
    fun testCreateScopeForbidden() = testEndpoint {
        postClient("/api/scopes", HttpStatusCode.Forbidden)
    }

    @Test
    fun testDeleteScopeForbidden() = testEndpoint {
        deleteClient("/api/scopes/${scope1Id}", HttpStatusCode.Forbidden)
        deleteClient("/api/scopes/${nonexistingScopeId}", HttpStatusCode.Forbidden)
    }
    //endregion

    //region test invalid scopes

    @Test
    fun testGetMissingScope() = testEndpoint {
        getClient("/api/scopes/${nonexistingScopeId}", HttpStatusCode.NotFound)
    }

    @Test
    fun testUpdateMissingScope() = testEndpoint {
        putAdmin("/api/scopes/${nonexistingScopeId}", HttpStatusCode.NotFound) {
            setBody("""{ "id":"$nonexistingScopeId", "value":"otherScope", "description":"Updated desc" }""")
        }
    }

    @Test
    fun testDeleteMissingScope() = testEndpoint {
        deleteAdmin("/api/scopes/${nonexistingScopeId}", HttpStatusCode.NotFound)
    }

    //endregion

    //region test normal functionality
    @Test
    fun testGetAllScopes() = testEndpoint {
        val r = getClient("/api/scopes")
        assertEquals(ContentType.Application.Json, r.contentType())

        val scopes: List<SystemScope> = Json.decodeFromString(r.bodyAsText())

        assertEquals(2, scopes.size)

        val scope1 = scopes.single { it.id == scope1Id }
        val scope2 = scopes.single { it.id == scope2Id }

        assertEquals(SystemScope(scope1Id, "test", "Test Scope Description"), scope1)
        assertEquals(SystemScope(scope2Id, "test2", "Other Scope Description"), scope2)
    }

    @Test
    fun testGetScope1() = testEndpoint {
        val scope1: SystemScope = Json.decodeFromString(getClient("/api/scopes/${scope1Id}").bodyAsText())
        assertEquals(SystemScope(scope1Id, "test", "Test Scope Description"), scope1)
    }

    @Test
    fun testGetScope2() = testEndpoint {
        val scope2: SystemScope = Json.decodeFromString(getClient("/api/scopes/${scope2Id}").bodyAsText())
        assertEquals(SystemScope(scope2Id, "test2", "Other Scope Description"), scope2)
    }

    @Test
    fun testUpdateScope2() = testEndpoint {
        val r = putAdmin("/api/scopes/${scope2Id}", HttpStatusCode.OK) {
            setBody("""{ "id":"$scope2Id", "value":"otherScope", "description":"Updated desc" }""")
        }
        val scope = Json.decodeFromString<SystemScope>(r.bodyAsText())
        assertEquals(SystemScope(scope2Id, "otherScope", "Updated desc"), scope)

        val serviceScope = testContext.scopeService.getById(scope2Id)

        assertEquals(scope, serviceScope)

    }

    @Test
    fun testUpdateInconsistentScope() = testEndpoint {
        val r = putAdmin("/api/scopes/${scope2Id}", HttpStatusCode.BadRequest) {
            setBody("""{ "id":"$scope1Id", "value":"otherScope", "description":"Updated desc" }""")
        }
        val resp = Json.parseToJsonElement(r.bodyAsText())
        val expected = buildJsonObject {
            put("error", JsonPrimitive("invalid_request"))
            put("error_description", JsonPrimitive("Could not update scope. Scope ids to not match: got ${scope2Id} and ${scope1Id}"))
        }
        assertEquals(expected, resp)
    }

    @Test
    fun testCreateScope() = testEndpoint {
        val r = postAdmin("/api/scopes") {
            setBody("""{ "value":"foo", "description":"Created description" }""")
        }
        val t = r.bodyAsText()
        val scope = Json.decodeFromString<SystemScope>(t)
        assertEquals("foo", scope.value)
        assertEquals("Created description", scope.description)
        assertEquals(false, scope.isRestricted)
        assertEquals(null, scope.icon)
        assertEquals(false, scope.isDefaultScope)

        val scopeId = assertNotNull(scope.id)
        val serviceScope = testContext.scopeService.getById(scopeId)
        assertEquals(scope, serviceScope)
    }

    @Test
    fun testDeleteScope() = testEndpoint {
        assertNotNull(testContext.scopeService.getById(scope1Id))

        val r = deleteAdmin("/api/scopes/$scope1Id", HttpStatusCode.OK)

        assertNull(testContext.scopeService.getById(scope1Id))
    }

    //endregion
}
