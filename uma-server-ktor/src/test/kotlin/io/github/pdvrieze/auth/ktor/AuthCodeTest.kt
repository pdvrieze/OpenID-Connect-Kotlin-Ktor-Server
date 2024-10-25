package io.github.pdvrieze.auth.ktor

import com.nimbusds.jwt.SignedJWT
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import org.junit.Before
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.web.TokenAPI
import org.mitre.openid.connect.filter.AuthTokenResponse
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
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

    lateinit var nonRedirectingClient: HttpClient

    var scope1Id: Long = -1L
    var scope2Id: Long = -1L

    @Before
    override fun setUp() {
        super.setUp()

        scope1Id = testContext.scopeRepository.save(SystemScope("scope1")).id!!
        scope2Id = testContext.scopeRepository.save(SystemScope("scope2")).id!!
    }

    @Test
    fun testSetup() {
        val client = assertNotNull(testContext.clientDetailsService.loadClientByClientId(clientId), "Missing client")
        assertNotNull(client.clientSecret, "Missing client secret")
        assertTrue(client.isAllowRefresh)
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
        val fragParams: Map<String, List<String?>> = respUri.fragment.splitToSequence('&')
            .map {
                val i = it.indexOf('=')
                when  {
                    i<0 -> it.decodeURLQueryComponent() to null
                    else -> it.substring(0, i).decodeURLQueryComponent() to it.substring(i + 1).decodeURLQueryComponent()
                }
            }.groupBy { it: Pair<String, String?> -> it.first }
            .mapValues { it: Map.Entry<String, List<Pair<String, String?>>> -> it.value.map { it.second } }


        val accessToken = assertNotNull(fragParams["access_token"]?.singleOrNull())
        assertEquals("Bearer", fragParams["token_type"]?.singleOrNull())

        val accessJWT = SignedJWT.parse(accessToken)
        assertTrue(accessJWT.verify(JWT_VERIFIER))

        assertEquals("user", accessJWT.jwtClaimsSet.subject)

    }

    @Test
    fun testClientCredentialsGrant() = testEndpoint {
        val r = nonRedirectingClient.submitForm(
            "/token",
            formParameters = parameters {
                append("grant_type", "client_credentials")
                append("scope", "scope1")
            }
        ) {
            basicAuth(clientId, clientSecret)
        }
        assertEquals(HttpStatusCode.OK, r.status)
        val accessTokenResponse = r.body<AuthTokenResponse>()// Json.parseToJsonElement(r2.bodyAsText()).jsonObject
        assertEquals("bearer", accessTokenResponse.tokenType.lowercase())
        val accessToken = SignedJWT.parse(accessTokenResponse.accessToken)
        assertTrue(accessToken.verify(JWT_VERIFIER))

        assertNull(accessTokenResponse.refreshToken, "Not allowed per RFC 6749, section 4.4.3")

        assertEquals("MyClient", accessToken.jwtClaimsSet.subject)
    }

    @Test
    fun testRefreshAccessToken() = testEndpoint {
        val tokenParams = mapOf("client_id" to clientId, "scope" to "offline_access")
        val req = AuthenticatedAuthorizationRequest(
            AuthorizationRequest(tokenParams, clientId, scope = setOf("offline_access")),
            SavedUserAuthentication("user")
        )
        val origToken = testContext.tokenService.createAccessToken(req, true)
        val refreshToken = assertNotNull(origToken.refreshToken)
        val r = submitClient(
            url = "/token",
            formParameters = parameters {
                append("grant_type", "refresh_token")
                append("refresh_token", refreshToken.value)
            }
        )
        val b = r.bodyAsText()
        val refreshedTokenResponse = Json.decodeFromString<AuthTokenResponse>(b)
        val accessToken = SignedJWT.parse(refreshedTokenResponse.accessToken)
        assertTrue(accessToken.verify(JWT_VERIFIER))

        val cs = accessToken.jwtClaimsSet
        assertEquals("user", cs.subject)
        assertEquals("MyClient", cs.getStringClaim("azp"))
        assertEquals("https://example.com/", cs.issuer)
        assertEquals("at+jwt", cs.getStringClaim("typ")) // required by RFC9068 for plain access tokens

        val n = Instant.now()
        assertTrue(n.isAfter(cs.issueTime.toInstant()))
        assertTrue(n.isBefore(cs.expirationTime.toInstant()))
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
        val accessTokenResponse = r2.body<AuthTokenResponse>()// Json.parseToJsonElement(r2.bodyAsText()).jsonObject
        assertEquals("bearer", accessTokenResponse.tokenType.lowercase())
        val accessToken = SignedJWT.parse(accessTokenResponse.accessToken)


        assertTrue(accessToken.verify(JWT_VERIFIER))

        val cs = accessToken.jwtClaimsSet

        assertEquals("https://example.com/", cs.issuer)
        assertEquals("user", cs.subject)
        assertEquals("at+jwt", cs.getStringClaim("typ")) // required by RFC9068 for plain access tokens

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
