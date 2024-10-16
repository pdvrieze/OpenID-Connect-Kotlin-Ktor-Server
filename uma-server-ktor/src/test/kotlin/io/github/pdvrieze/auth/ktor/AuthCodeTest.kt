package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.repository.exposed.AccessTokenPermissions
import io.github.pdvrieze.auth.repository.exposed.AccessTokens
import io.github.pdvrieze.auth.repository.exposed.AuthenticationHolders
import io.github.pdvrieze.auth.repository.exposed.AuthorizationCodes
import io.github.pdvrieze.auth.repository.exposed.SystemScopes
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.web.TokenAPI
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.web.FormAuthEndpoint
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class AuthCodeTest: ApiTest(TokenAPI, PlainAuthorizationRequestEndpoint, FormAuthEndpoint) {

    lateinit var clientId: String
    lateinit var clientSecret: String

    lateinit var nonRedirectingClient: HttpClient

    var scope1Id: Long = -1L
    var scope2Id: Long = -1L

    override val deletableTables: List<Table>
        get() = listOf(AuthorizationCodes, AuthenticationHolders, AccessTokenPermissions, AccessTokens)

    @Before
    override fun setUp() {
        super.setUp()

        transaction { SystemScopes.deleteAll() }

        testContext.clientService.allClients.toList().forEach { client ->
            testContext.clientService.deleteClient(client)
        }

        scope1Id = testContext.scopeRepository.save(SystemScope("scope1")).id!!
        scope2Id = testContext.scopeRepository.save(SystemScope("scope2")).id!!

        clientSecret = testContext.clientService.generateClientSecret()!!
        val newClient = ClientDetailsEntity(
            clientId = "MyClient",
            clientSecret = clientSecret,
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
    fun testGetAuthorizationCodeNoState() = testEndpoint {
        val r = getUser("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])

        assertNotNull(testContext.authorizationCodeRepository.getByCode(code))

        assertNull(respUri.parameters["state"])
    }

    @Test
    fun testGetAuthorizationCodeWithState() = testEndpoint {
        val state = UUID.randomUUID().toString()
        val r = getUser("/authorize?response_type=code&client_id=$clientId&state=$state", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])
        assertNotNull(testContext.authorizationCodeRepository.getByCode(code))

        assertEquals(state, respUri.parameters["state"])
    }

    @Test
    fun testAuthorizationCodeFlowSimpleNoState() = testEndpoint {
        val r = getUser("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])

        val r2 = getUnAuth("/token?grant_type=authorization_code&code=$code", client = nonRedirectingClient) {
            basicAuth(clientId, clientSecret)
        }
        assertEquals(HttpStatusCode.OK, r2.status)
        // TODO("exchange code for token")
    }

    override fun configureApplication(testBuilder: ApplicationTestBuilder) {
        super.configureApplication(testBuilder)
        nonRedirectingClient = testBuilder.createClient { followRedirects = false }
    }

    companion object {
        const val REDIRECT_URI = "http://localhost:1234/clientApp"
    }

}
