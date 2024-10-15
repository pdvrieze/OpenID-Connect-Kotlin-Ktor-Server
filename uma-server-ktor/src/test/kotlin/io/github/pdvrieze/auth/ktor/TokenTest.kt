package io.github.pdvrieze.auth.ktor

import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.github.pdvrieze.auth.repository.exposed.SystemScopes
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.server.testing.*
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.web.ScopeAPI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class TokenTest: ApiTest(ScopeAPI) {

    lateinit var clientId: String

    lateinit var nonRedirectingClient: HttpClient

    var scope1Id: Long = -1L
    var scope2Id: Long = -1L

    override val deletableTables: List<Table>
        get() = listOf(SystemScopes)

    @Before
    override fun setUp() {
        super.setUp()

        transaction { SystemScopes.deleteAll() }

        testContext.clientService.allClients.toList().forEach { client ->
            testContext.clientService.deleteClient(client)
        }

        scope1Id = testContext.scopeRepository.save(SystemScope("scope1")).id!!
        scope2Id = testContext.scopeRepository.save(SystemScope("scope2")).id!!

        val newClient = ClientDetailsEntity(
            clientId = "MyClient",
            clientSecret = testContext.clientService.generateClientSecret(),
            redirectUris = setOf(REDIRECT_URI),
            scope = setOf("scope1", "scope2"),
        )

        clientId = testContext.clientService.saveNewClient(newClient).clientId!!
    }

    @Test
    fun testSetup() {
        val client = assertNotNull(testContext.clientService.loadClientByClientId(clientId), "Missing client")
        assertNotNull(client.clientSecret, "Missing client secret")
    }

    @Test
    fun testAuthorizationCodeFlowSimpleNoState() = testEndpoint {
        val r = getUser("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        assertEquals(REDIRECT_URI, respUri.protocolWithAuthority)
        val code = assertNotNull(respUri.parameters["code"])
        val jwt = assertIs<SignedJWT>(JWTParser.parse(code))

    }

    override fun ApplicationTestBuilder.configureApplication() {
        nonRedirectingClient = createClient { followRedirects = false }
    }

    companion object {
        const val REDIRECT_URI = "http://localhost:1234/clientApp"
    }

}
