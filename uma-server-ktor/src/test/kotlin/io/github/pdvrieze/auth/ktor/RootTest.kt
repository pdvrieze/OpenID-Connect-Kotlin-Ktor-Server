package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.testing.*
import org.junit.Before
import org.mitre.openid.connect.web.RootController
import org.mitre.web.util.OpenIdContext
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RootTest {

    private lateinit var testContext: OpenIdContext

    @Before
    fun setUp() {
        testContext = OpenIdConfigurator("https://example.com/").resolveDefault()
/*
        transaction {
            UserInfos.insert { st ->
                st[sub] = "user"
                st[email] = "user@example.com"
                st[givenName] = "Joe"
                st[familyName] = "Bloggs"
            }
        }
*/
    }

    @Test
    fun testRoot() = testApplication {
        configureApplication()


        val recv1 = client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType())
        }.bodyAsText()

        val recv2 = client.get("/home").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType())
        }.bodyAsText()

        val recv3 = client.get("/index").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType())
        }.bodyAsText()

        assertEquals(recv1, recv2)
        assertEquals(recv1, recv3)
    }

    @Test
    fun testAbout() = testApplication {
        configureApplication()

        val recv = client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }.bodyAsText()

        assertEquals("foo", recv)
    }

    @Test
    fun testStats() = testApplication {
        configureApplication()

        client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }
    }

    @Test
    fun testContacts() = testApplication {
        configureApplication()

        client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }
    }


    private fun ApplicationTestBuilder.configureApplication() {
        application {
            install(OpenIdContextPlugin) { context = testContext }
            install(Authentication) {
                basic {
                    realm = "test-ktor-openid"
                    this.validate { credentials ->
                        // temporary testing
                        if (credentials.name == "admin" && credentials.password == "secret") {
                            UserIdPrincipal("admin")
                        } else {
                            null
                        }
                    }
                }
            }

            configureRouting() {
                with(RootController) { addRoutes() }
            }
        }
    }
}
