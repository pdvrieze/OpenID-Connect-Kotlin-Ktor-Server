package io.github.pdvrieze.auth.ktor

import com.nimbusds.jwt.SignedJWT
import io.github.pdvrieze.auth.repository.exposed.AccessTokenPermissions
import io.github.pdvrieze.auth.repository.exposed.AccessTokens
import io.github.pdvrieze.auth.repository.exposed.AuthenticationHolderRequestParameters
import io.github.pdvrieze.auth.repository.exposed.AuthenticationHolderResponseTypes
import io.github.pdvrieze.auth.repository.exposed.AuthenticationHolderScopes
import io.github.pdvrieze.auth.repository.exposed.AuthenticationHolders
import io.github.pdvrieze.auth.repository.exposed.AuthorizationCodes
import io.github.pdvrieze.auth.repository.exposed.SavedUserAuthAuthorities
import io.github.pdvrieze.auth.repository.exposed.SavedUserAuths
import io.github.pdvrieze.auth.repository.exposed.SystemScopes
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.web.TokenAPI
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.util.asString
import org.mitre.web.FormAuthEndpoint
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthCodeTest: ApiTest(TokenAPI, PlainAuthorizationRequestEndpoint, FormAuthEndpoint) {

    lateinit var clientId: String
    lateinit var clientSecret: String

    lateinit var nonRedirectingClient: HttpClient

    var scope1Id: Long = -1L
    var scope2Id: Long = -1L

    override val deletableTables: List<Table>
        get() = listOf(
            AccessTokenPermissions, AccessTokens,
            AuthorizationCodes,
            AuthenticationHolderResponseTypes, AuthenticationHolderScopes, AuthenticationHolderRequestParameters, AuthenticationHolders,
            SavedUserAuthAuthorities, SavedUserAuths,
        )

    @Before
    override fun setUp() {
        super.setUp()

        transaction { SystemScopes.deleteAll() }

        testContext.clientDetailsService.allClients.toList().forEach { client ->
            testContext.clientDetailsService.deleteClient(client)
        }

        scope1Id = testContext.scopeRepository.save(SystemScope("scope1")).id!!
        scope2Id = testContext.scopeRepository.save(SystemScope("scope2")).id!!

        clientSecret = testContext.clientDetailsService.generateClientSecret()!!
        val newClient = ClientDetailsEntity(
            clientId = "MyClient",
            clientSecret = clientSecret,
            redirectUris = setOf(REDIRECT_URI),
            scope = setOf("scope1", "scope2"),
            accessTokenValiditySeconds = 60*5, // 5 minutes
        )

        clientId = testContext.clientDetailsService.saveNewClient(newClient).clientId!!
    }

    @Test
    fun testSetup() {
        val client = assertNotNull(testContext.clientDetailsService.loadClientByClientId(clientId), "Missing client")
        assertNotNull(client.clientSecret, "Missing client secret")
        assertEquals(300, client.accessTokenValiditySeconds)
    }

    @Test
    fun testGetAuthorizationCodeNoState() = testEndpoint {
        val r = getUser("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])

        val storedCode = assertNotNull(testContext.authorizationCodeRepository.getByCode(code))
        val storedHolder = assertNotNull(storedCode.authenticationHolder)
        val storedUser = assertNotNull(storedHolder.userAuth, "Missing user auth in authorization code acquisition")
        assertEquals("user", storedUser.name)
        assertTrue(storedUser.isAuthenticated)

        assertNull(respUri.parameters["state"])
    }

    @Test
    fun testImplicitFlowNoState() = testEndpoint {
        val r = getUser("/authorize?response_type=token&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!

        assertNull(respUri.parameters["state"])
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val accessToken = assertNotNull(respUri.fragment)

        val accessJWT = SignedJWT.parse(accessToken)
        assertTrue(accessJWT.verify(JWT_VERIFIER))

        assertEquals("user", accessJWT.jwtClaimsSet.subject)

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

        val r2 = nonRedirectingClient.submitForm(
            "/token",
            formParameters = parameters {
                append("grant_type", "authorization_code")
                append("code", code)
            }
        ) {
            basicAuth(clientId, clientSecret)
        }
        assertEquals(HttpStatusCode.OK, r2.status)
        val accessTokenResponse = r2.body<JsonObject>()// Json.parseToJsonElement(r2.bodyAsText()).jsonObject
        assertEquals("Bearer", accessTokenResponse["token_type"].asString())
        val accessToken = SignedJWT.parse(accessTokenResponse["access_token"].asString())


        assertTrue(accessToken.verify(JWT_VERIFIER))

        val cs = accessToken.jwtClaimsSet

        assertEquals("https://example.com/", cs.issuer)
        assertEquals("user", cs.subject)

        val exp = assertNotNull(cs.expirationTime, "Missing expiration time").toInstant()
        val n = Instant.now()
        assertTrue(n.isBefore(exp))
        assertTrue((n + Duration.ofMinutes(5)).isAfter(exp))

        // iat (issued at) may be present (in seconds from epoch)
        // expect audience (aud) to include auth server: RFC7523 (ch 3, bullet 3)
        // expect exp (expiration)
        // opt expect amr = [ "password" ] - authentication methods used
        // opt expect authorized party - the client id that received the token

        // TODO("exchange code for token")
    }

    override fun configureApplication(testBuilder: ApplicationTestBuilder) {
        super.configureApplication(testBuilder)
        nonRedirectingClient = testBuilder.createClient {
            followRedirects = false
            install(ContentNegotiation) {
                json(Json { prettyPrint = true })
            }
        }
    }

    companion object {
        const val REDIRECT_URI = "http://localhost:1234/clientApp"

    }

}
