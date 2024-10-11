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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import org.jetbrains.exposed.sql.insert
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.discovery.view.WebfingerViews
import org.mitre.discovery.web.DiscoveryEndpoint
import org.mitre.web.util.OpenIdContext
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DiscoveryTest {

    private lateinit var testContext: OpenIdContext

    @Before
    fun setUp() {
        testContext = OpenIdConfigurator("https://example.com/").resolveDefault()
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
            val json = assertIs<JsonObject>(Json.parseToJsonElement(bodyAsText()))

            val subj = assertIs<JsonPrimitive>(json["subject"])
            assertTrue(subj.isString)
            assertEquals("user@example.com", subj.content)

            val links = assertIs<JsonArray>(json["links"])
            assertEquals(1, links.size)
            val link = assertIs<JsonObject>(links.single())

            val rel = assertIs<JsonPrimitive>(link["rel"])
            assertTrue(rel.isString)
            assertEquals("http://openid.net/specs/connect/1.0/issuer", rel.content)

            val href = assertIs<JsonPrimitive>(link["href"])
            assertTrue(href.isString)
            assertEquals("https://example.com/", href.content)
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

    @Test
    fun testGetConfiguration() = testApplication {
        configureApplication()

        client.get("/.well-known/openid-configuration").apply {
            assertEquals(200, status.value)
            assertEquals(ContentType.Application.Json, contentType())

            val actual = assertIs<JsonObject>(Json.parseToJsonElement(bodyAsText()))
            for (key in arrayOf("issuer", "authorization_endpoint", "token_endpoint", "token_endpoint_auth_methods_supported",
                                "token_endpoint_auth_signing_alg_values_supported", "userinfo_endpoint", /*"check_session_iframe",*/
                                "end_session_endpoint", "jwks_uri", "registration_endpoint", "scopes_supported",
                                "response_types_supported", /*"acr_values_supported",*/ "subject_types_supported",
                                "userinfo_signing_alg_values_supported", "userinfo_encryption_alg_values_supported",
                                "userinfo_encryption_enc_values_supported", "id_token_signing_alg_values_supported",
                                "id_token_encryption_alg_values_supported", "id_token_encryption_enc_values_supported",
                                "request_object_signing_alg_values_supported", /*"display_values_supported",*/ "claim_types_supported",
                                "claims_supported", "claims_parameter_supported", "service_documentation", /*"ui_locales_supported",*/)) {
                assertTrue(actual.containsKey(key), "provider configuration misses key: $key")
                assertNotEquals(actual[key], JsonPrimitive(""))
            }

            assertEquals(actual["issuer"], JsonPrimitive("https://example.com/"))
            assertEquals(actual["authorization_endpoint"], JsonPrimitive("https://example.com/authorize"))
            assertEquals(actual["response_types_supported"], buildJsonArray { add(JsonPrimitive("code")); add(JsonPrimitive("token"))})
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
