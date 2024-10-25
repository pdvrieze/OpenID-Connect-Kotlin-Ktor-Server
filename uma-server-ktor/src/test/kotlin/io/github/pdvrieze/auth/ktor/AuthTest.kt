package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.server.testing.*
import org.mitre.web.FormAuthEndpoint
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthTest : ApiTest(FormAuthEndpoint) {

    private fun verifyPwd(credential: UserPasswordCredential): Boolean {
        return credential.name == "admin" && credential.password == "secret"
    }

    @Test
    fun testFormLoginForm() = testEndpoint {

        client.get("/login").apply {
            assertTrue(status.isSuccess(), "Unexpected response: $status")

            val resp = bodyAsText()

            val userNameInput = Regex("<input\\b[^>]*\\bname=(['\"])username\\1[^>]*>").findAll(resp).toList()
            assertNotEquals(0, userNameInput.size, "No username input")
            for (input in userNameInput) {
                assertContains(input.value, Regex("type=(['\"])text\\1"), message = "Incorrect username input")
            }

            val passwordInput = Regex("<input\\b[^>]*\\bname=(['\"])password\\1[^>]*").findAll(resp).toList()
            assertNotEquals(0, passwordInput.size, "No password input")
            for (input in passwordInput) {
                assertContains(input.value, Regex("type=(['\"])password\\1"), message = "Incorrect password input")
            }
        }
    }

    @Test
    fun testFormLoginFormRedirect() = testEndpoint {

        client.get("/login?redirect_uri=/user").apply {
            assertTrue(status.isSuccess(), "Unexpected response: $status")

            val resp = bodyAsText()

            val redirectInput = Regex("<input\\b[^>]*\\bname=(['\"])redirect\\1[^>]*>").findAll(resp).toList()
            assertNotEquals(0, redirectInput.size, "No redirect input")
            for (input in redirectInput) {
                val target = Regex("""\bvalue=(['"])([^\\1]*)\1""").findAll(input.value).toList()
                assertEquals(1, target.size, "Only a single value for an input allowed: '${input.value}'")
                assertEquals("/user", target.single().groups[2]?.value, "Incorrect or missing redirect value")
            }
        }
    }

    @Test
    public fun testMissingUser() = testEndpoint {

        val loginResp = client.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "user")
                append("password", "secret")
            }
        )
        assertEquals(HttpStatusCode.Unauthorized, loginResp.status)
    }

    @Test
    public fun testInvalidPwd() = testEndpoint {

        val loginResp = client.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "admin")
                append("password", "invalid")
            }
        )
        assertEquals(HttpStatusCode.Unauthorized, loginResp.status)
    }

    @Test
    public fun testDoLogin() = testEndpoint {

        val nonRedirectingClient = createClient {
            followRedirects = false
        }

        val loginResp = nonRedirectingClient.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "admin")
                append("password", "secret")
            }
        )

        assertEquals("/", loginResp.headers[HttpHeaders.Location])
        val rawCookie = assertNotNull(loginResp.headers[HttpHeaders.SetCookie], "Cookie should exist")
        val cookie = parseServerSetCookieHeader(rawCookie)

        assertEquals(OpenIdSessionStorage.COOKIE_NAME, cookie.name)
    }

    @Test
    public fun testLoginUserInfo() = testApplication {
        customConfigure()

        val client = createClient {
            followRedirects = true
            install(HttpCookies)
        }

        var resp = client.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "admin")
                append("password", "secret")
                append("redirect", "/user")
            }
        )
        if (resp.status == HttpStatusCode.Found) {
            val location = resp.headers[HttpHeaders.Location]!!
            assertEquals("/user", location)
            resp = client.get(location)
        }

        assertEquals(HttpStatusCode.OK, resp.status, "Unexpected response: ${resp.status}")

        assertNull(resp.headers[HttpHeaders.Location])

        val content = resp.bodyAsText()
        assertEquals("admin", content)
    }

    @Test
    public fun testDoLoginRedirect() = testApplication {
        customConfigure()

        val nonRedirectingClient = createClient {
            followRedirects = false
        }

        val loginResp = nonRedirectingClient.submitForm(
            url = "/login",
            formParameters = parameters {
                append("username", "admin")
                append("password", "secret")
                append("redirect", "/user")
            }
        )

        assertEquals("/user", loginResp.headers[HttpHeaders.Location])
        val rawCookie = assertNotNull(loginResp.headers[HttpHeaders.SetCookie], "Cookie should exist")
        val cookie = parseServerSetCookieHeader(rawCookie)

        assertEquals(OpenIdSessionStorage.COOKIE_NAME, cookie.name)
        assertTrue(cookie.httpOnly)
        assertNull(cookie.expires)

    }

    override fun configureApplication(testBuilder: ApplicationTestBuilder) {
        super.configureApplication(testBuilder)
    }

    private fun ApplicationTestBuilder.customConfigure() {
        application {
            install(OpenIdContextPlugin) { context = testContext }
            install(Sessions) {
                cookie<OpenIdSessionStorage>(OpenIdSessionStorage.COOKIE_NAME, /*SessionStorageMemory()*/) {
                    this.cookie.apply {
                        httpOnly = true
                        maxAge =  null //session only
                    }
                }
            }
            authentication {
                session<OpenIdSessionStorage> {
                    validate { session ->
                        session.principal
                    }
                }
            }

            configureRouting() {
                with(FormAuthEndpoint) { addRoutes() }
                authenticate {
                    get("/user") {
                        val user = call.authentication.principal<UserIdPrincipal>()
                            ?: return@get call.respond(HttpStatusCode.Unauthorized)

                        call.respondText(user.name)
                    }
                }

            }
        }
    }
}
