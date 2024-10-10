package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.github.pdvrieze.auth.uma.repository.exposed.UserInfos
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.discovery.view.WebfingerViews
import org.mitre.discovery.web.DiscoveryEndpoint
import org.mitre.web.util.OpenIdContext
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WebFingerTest {

    private lateinit var testContext: OpenIdContext

    @Before
    fun setUp() {
        testContext = OpenIdConfigurator("http://example.com/").resolveDefault()
        transaction {
            UserInfos.insert { st ->
                st[sub] = "user"
                st[email] = "user@example.com"
                st[givenName] = "Joe"
                st[familyName] = "Bloggs"
            }
        }
    }

    @Test
    fun testWebFinger() = testApplication {
        configureApplication()

        client.get("/.well-known/webfinger?resource=user%40example.com").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(WebfingerViews.CT_JRD, contentType())
            val json = Json.parseToJsonElement(bodyAsText())
            assertTrue { json is JsonObject }

        }
    }

    @Test
    fun testMissingResource() = testApplication {
        configureApplication()

        client.get("/.well-known/webfinger").apply {
            assertEquals(400, status.value)
        }
    }

    @Test
    fun testMissingUser() = testApplication {
        configureApplication()

        client.get("/.well-known/webfinger?resource=joe%40example.com").apply {
            assertEquals(404, status.value)
        }
    }

    private fun ApplicationTestBuilder.configureApplication() {
        application {
            install(OpenIdContextPlugin) { context = testContext }

            configureRouting() {
                with(DiscoveryEndpoint) { addRoutes() }
            }
        }
    }
}
