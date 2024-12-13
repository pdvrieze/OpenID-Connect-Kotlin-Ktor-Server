package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.testing.*
import org.mitre.openid.connect.web.RootController
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RootTest : ApiTest(RootController) {

    @Test
    fun testRoot() = testEndpoint<Unit> {

        val recv1 = client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType()?.withoutParameters())
        }.bodyAsText()

        val recv2 = client.get("/home").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType()?.withoutParameters())
        }.bodyAsText()

        val recv3 = client.get("/index").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(ContentType.Text.Html, contentType()?.withoutParameters())
        }.bodyAsText()

        assertEquals(recv1, recv2)
        assertEquals(recv1, recv3)
    }

    @Test
    fun testAbout() = testEndpoint<Unit> {
        val recv = client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }.bodyAsText()
        assertContains(recv, "<h2>About</h2>")
    }

    @Test
    fun testStats() = testEndpoint<Unit> {
        client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }
    }

    @Test
    fun testContacts() = testEndpoint<Unit> {
        client.get("/").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }
    }

    @Test
    fun testManage() = testEndpoint<Unit> {
        getAdmin("/manage").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
        }
    }

    @Test
    fun testManageUnAuth() = testEndpoint<Unit> {
        client.get("/manage").apply {
            assertEquals(HttpStatusCode.Unauthorized, status, "Unexpected response : $status" )
        }
    }

    private fun ApplicationTestBuilder.configureApplication2() {
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

            configureRouting {
                with(RootController) { addRoutes() }
            }
        }
    }
}
