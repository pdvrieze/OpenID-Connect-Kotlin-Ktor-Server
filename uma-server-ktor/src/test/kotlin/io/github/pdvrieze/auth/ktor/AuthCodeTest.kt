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
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.web.TokenAPI
import org.mitre.openid.connect.filter.AuthTokenResponse
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.web.FormAuthEndpoint
import org.mitre.web.OpenIdSessionStorage
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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

    private fun preAuthorizeAccess() {
        testContext.approvedSiteService.createApprovedSite(clientId, "user", Date.from(Instant.now().plusSeconds(60)), CLIENT_SCOPE)
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
        preAuthorizeAccess()
        val r = getUser("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])

        val storedCode = assertNotNull(testContext.authorizationCodeRepository.getByCode(code))
        val storedHolder = assertNotNull(storedCode.authenticationHolder)
        val storedUser = assertNotNull(storedHolder.userAuthentication, "Missing user auth in authorization code acquisition")
        assertEquals(setOf("offline_access", "scope1", "scope2"), storedHolder.authorizationRequest.scope)
        assertEquals("user", storedUser.name)
        assertTrue(storedUser.isAuthenticated)

        assertNull(respUri.parameters["state"])
        assertNull(respUri.parameters["scope"])
    }

    @Test
    fun testGetAuthorizationCodeState() = testEndpoint {
        preAuthorizeAccess()
        val r = getUser("/authorize?response_type=code&client_id=$clientId&state=34u923&scope=scope2", HttpStatusCode.Found, client = nonRedirectingClient)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)
        val code = assertNotNull(respUri.parameters["code"])
        assertEquals("34u923", respUri.parameters["state"])

        val storedCode = assertNotNull(testContext.authorizationCodeRepository.getByCode(code))
        val storedHolder = assertNotNull(storedCode.authenticationHolder)
        val storedUser = assertNotNull(storedHolder.userAuthentication, "Missing user auth in authorization code acquisition")
        assertEquals(setOf("scope2"), storedHolder.authorizationRequest.scope)
        assertEquals("user", storedUser.name)
        assertTrue(storedUser.isAuthenticated)
    }

    @Test
    fun testGetAuthorizationCodeStateNoAuth() = testEndpoint {
        val r = getUnAuth("/authorize?response_type=code&client_id=$clientId&state=34u923&scope=scope2", HttpStatusCode.Unauthorized, client = nonRedirectingClient)
        assertNull(r.headers[HttpHeaders.Location])
        assertEquals(ContentType.Text.Html, r.contentType()?.withoutParameters())

        val responseText = r.bodyAsText()
        val regex = Regex("(<input\\b[^>]*\\bname=(['\"])password\\2[^>]*>)")
        val matches = regex.findAll(responseText)
        assertEquals(1, matches.count())

        val form = Regex("(<form\\b[^>]*>)").findAll(responseText).single().groups[1]!!.value

        val action = Regex("\\baction=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
        val method = Regex("\\bmethod=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value

        assertEquals("https://example.com/authorize/login", action)
        assertEquals("post", method)
    }

    @Test
    fun testGetAuthorizationCodeStateAuthenticatedNotAuthorized() = testEndpoint {
        val r = getUser("/authorize?response_type=code&client_id=$clientId&state=34u923&scope=scope2", HttpStatusCode.OK, client = nonRedirectingClient)
        assertNull(r.headers[HttpHeaders.Location])
        assertEquals(ContentType.Text.Html, r.contentType()?.withoutParameters())

        val responseText = r.bodyAsText()
        val inputs = Regex("<input\\b[^>]*\\bname=(['\"])([^'\"]*)\\1[^>]*>").findAll(responseText).groupBy(
            keySelector = { it.groups[2]?.value },
            valueTransform = { it.value }
        )

        assertNull(inputs["passwords"])
        assertEquals(1, assertNotNull(inputs["scope_scope2"]).size) // we only ask for scope 2
        assertEquals(3, assertNotNull(inputs["remember"]).size)

        val sessionCookie = r.setCookie().singleOrNull { it.name == OpenIdSessionStorage.COOKIE_NAME }
        assertNotNull(sessionCookie) // a session cookie is required
        // We use sessions for CSRF
        // assertEquals(1, assertNotNull(inputs["SDFHLK_CSRF"]).size) // important to ensure request from here
        assertEquals(1, assertNotNull(inputs["deny"]).size)
        assertEquals(1, assertNotNull(inputs["authorize"]).size)
        assertEquals(1, assertNotNull(inputs["user_oauth_approval"]).size)


        val form = Regex("<form\\b[^>]*\\bname=\"confirmationForm\"[^>]*>").findAll(responseText).single().value

        val action = Regex("\\baction=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
        val method = Regex("\\bmethod=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value

        assertEquals("https://example.com/authorize", action)
        assertEquals("post", method)
    }

    @Test
    fun testGetAuthorizationCodeStateNoAuthPromptNone() = testEndpoint {
        val r = getUnAuth("/authorize?response_type=code&client_id=$clientId&redirect_uri=$REDIRECT_URI&prompt=none&state=34u923&scope=scope2", HttpStatusCode.Found, client = nonRedirectingClient)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!
        val actualBase = URLBuilder(respUri.protocolWithAuthority).apply {
            pathSegments = respUri.segments
        }.buildString()

        assertEquals(REDIRECT_URI, actualBase)

        assertEquals("login_required", respUri.parameters["error"])
        assertEquals("34u923", respUri.parameters["state"])
    }

    @Test
    fun testImplicitFlowNoState() = testEndpoint {
        preAuthorizeAccess()
        val r = getUser("/authorize?response_type=token&scope=offline_access%20scope2&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
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
        assertFalse("refresh_token" in fragParams)

        val accessJWT = SignedJWT.parse(accessToken)
        assertTrue(accessJWT.verify(JWT_VERIFIER))

        assertEquals("user", accessJWT.jwtClaimsSet.subject)

        val expectedScope = setOf("offline_access", "scope2")
        assertEquals(expectedScope, accessJWT.jwtClaimsSet.getStringClaim("scope").splitToSequence(" ").toSet())
        assertEquals("at+jwt", accessJWT.header.type.type.lowercase())

    }

    @Test
    fun testImplicitFlowState() = testEndpoint {
        preAuthorizeAccess()
        val r = getUser("/authorize?response_type=token&state=dsf890l&scope=scope1&client_id=$clientId", HttpStatusCode.Found, client = nonRedirectingClient)
        assertEquals(HttpStatusCode.Found, r.status)
        val respUri = parseUrl(assertNotNull(r.headers[HttpHeaders.Location]))!!

        assertEquals("dsf890l", respUri.parameters["state"])
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

        val expectedScope = setOf("scope1")
        assertEquals(expectedScope, accessJWT.jwtClaimsSet.getStringClaim("scope").splitToSequence(" ").toSet())
        assertEquals("at+jwt", accessJWT.header.type.type.lowercase())

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
        val requestTime = Instant.now()
        val req = AuthenticatedAuthorizationRequest(
            PlainAuthorizationRequest.Builder(clientId).also { b ->
//                b.requestParameters = tokenParams
                b.requestTime = requestTime
                b.scope = setOf("offline_access")
                b.requestTime = requestTime
            }.build(),
            SavedUserAuthentication("user")
 )
        val origToken = testContext.tokenService.createAccessToken(req, true, emptyMap())
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
        assertEquals("at+jwt", accessToken.header.type.type) // required by RFC9068 for plain access tokens

        val n = Instant.now()
        assertTrue(n.isAfter(cs.issueTime.toInstant()))
        assertTrue(n.isBefore(cs.expirationTime.toInstant()))
    }

    @Test
    fun testGetAuthorizationCodeWithState() = testEndpoint {
        preAuthorizeAccess()
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
        // Initial request starts login flow (and creates the session cookie)
        var sessionCookie = run {
            val loginResp = getUnAuth("/authorize?response_type=code&client_id=$clientId", HttpStatusCode.Unauthorized, client = nonRedirectingClient)
            assertNull(loginResp.headers[HttpHeaders.Location])
            assertEquals(ContentType.Text.Html, loginResp.contentType()?.withoutParameters())

            val responseText = loginResp.bodyAsText()

            val form = Regex("<form\\b[^>]*>").findAll(responseText).single().value

            val action = Regex("\\baction=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
            val method = Regex("\\bmethod=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
            assertEquals("post", method)
            assertEquals("https://example.com/authorize/login", action)

            loginResp.setCookie().single { it.name == OpenIdSessionStorage.COOKIE_NAME }
        }

        run { // Respond to the login form without the cookie (this should be invalid, CSRF)
            val missingSession = submitUnAuth(
                url = "/authorize/login",
                formParameters = Parameters.build {
                    append("userName", "user")
                    append("password", "userSecret")
                },
                statusCode = HttpStatusCode.BadRequest
            )
            val content = missingSession.bodyAsText()
            assertContains(content, "invalid_request")
            assertContains(content, "Missing session")
        }

        run { // Actually log in the user (with cookie)
            val withSession = submitUnAuth(
                url = "/authorize/login",
                formParameters = Parameters.build {
                    append("userName", "user")
                    append("password", "userSecret")
                },
                statusCode = HttpStatusCode.OK,
            ) {
                headers {
                    append(HttpHeaders.Cookie, renderCookieHeader(sessionCookie))
                }
            }

            sessionCookie = withSession.setCookie().single { it.name == OpenIdSessionStorage.COOKIE_NAME }

            val content = withSession.bodyAsText()
            val form = Regex("<form\\b[^>]*>").findAll(content).single { "logoutForm" !in it.value}.value

            val action = Regex("\\baction=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
            val method = Regex("\\bmethod=(['\"])([^'\"]*)\\1").findAll(form).single().groups[2]!!.value
            val inputs = Regex("<input\\b[^>]*\\bname=(['\"])([^'\"]*)\\1[^>]*>").findAll(content).groupBy(
                keySelector = { it.groups[2]?.value },
                valueTransform = { it.value }
            )

            assertEquals("post", method)
            assertEquals("https://example.com/authorize", action)

            assertContains(assertNotNull(inputs["scope_scope1"]?.singleOrNull()), "checkbox")
            assertContains(assertNotNull(inputs["scope_scope2"]?.singleOrNull()), "checkbox")
            assertContains(assertNotNull(inputs["scope_offline_access"]?.singleOrNull()), "checkbox")

            val remembers = assertNotNull(inputs["remember"])
            assertEquals(3, remembers.size)
            for (r in remembers) {
                assertContains(r, "radio")
            }
            assertTrue(remembers.count { "value=\"until-revoked\"" in it } == 1)
            assertTrue(remembers.count { "value=\"one-hour\"" in it } == 1)
            assertTrue(remembers.count { "value=\"none\"" in it } == 1)

            assertContains(assertNotNull(inputs["user_oauth_approval"]?.singleOrNull()), "hidden")
            assertContains(assertNotNull(inputs["authorize"]?.singleOrNull()), "submit")
            assertContains(assertNotNull(inputs["deny"]?.singleOrNull()), "submit")
        }

        run { // Approve the request
            val approved = submitUnAuth(
                url = "/authorize",
                formParameters = Parameters.build {
                    append("scope_scope1", "scope1")
                    append("scope_scope2", "scope2")
                    append("scope_offline_access", "offline_access")
                    append("remember", "one-hour")
                    append("authorize", "Authorize")
                    append("user_oauth_approval", "true")
                },
                statusCode = HttpStatusCode.Found,
            ) {
                headers {
                    append(HttpHeaders.Cookie, renderCookieHeader(sessionCookie))
                }
            }

            val respUri = parseUrl(assertNotNull(approved.headers[HttpHeaders.Location]))!!
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
            assertEquals("at+jwt", accessToken.header.type.type) // required by RFC9068 for plain access tokens

            val exp = assertNotNull(cs.expirationTime, "Missing expiration time").toInstant()
            val n = Instant.now()
            assertTrue(n.isBefore(exp))
            assertTrue((n + Duration.ofMinutes(5)).isAfter(exp))

        }

        // iat (issued at) may be present (in seconds from epoch)
        // expect audience (aud) to include auth server: RFC7523 (ch 3, bullet 3)
        // expect exp (expiration)
        // opt expect amr = [ "password" ] - authentication methods used
        // opt expect authorized party - the client id that received the token

        // TODO("exchange code for token")
    }

    @Test
    fun testAuthorizationCodeFlowSimpleNoStatePreAuthorized() = testEndpoint {
        preAuthorizeAccess()

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
        assertEquals("at+jwt", accessToken.header.type.type) // required by RFC9068 for plain access tokens

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
        val CLIENT_SCOPE = setOf("scope1", "scope2", "offline_access")
    }

}
