package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.uma.repository.exposed.UserInfos
import io.ktor.client.statement.*
import io.ktor.http.*
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
import org.mitre.util.oidJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DiscoveryTest : ApiTest(DiscoveryEndpoint) {

    @Before
    override fun setUp() {
        super.setUp()
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
    fun testWebFinger() = testEndpoint<Unit> {
        getUnAuth("/.well-known/webfinger?resource=user%40example.com").apply {
            assertTrue(status.isSuccess(), "Unexpected response : $status" )
            assertEquals(WebfingerViews.CT_JRD, contentType())
            val json = assertIs<JsonObject>(oidJson.parseToJsonElement(bodyAsText()))

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
    fun testMissingResource() = testEndpoint<Unit> {
        getUnAuth("/.well-known/webfinger", HttpStatusCode.BadRequest)
    }

    @Test
    fun testMissingUser() = testEndpoint<Unit> {
        getUnAuth("/.well-known/webfinger?resource=joe%40example.com", HttpStatusCode.NotFound)
    }

    @Test
    fun testGetConfiguration() = testEndpoint<Unit> {
        getUnAuth("/.well-known/openid-configuration").apply {
            assertEquals(200, status.value)
            assertEquals(ContentType.Application.Json, contentType())

            val actual = assertIs<JsonObject>(oidJson.parseToJsonElement(bodyAsText()))
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

            assertEquals(JsonPrimitive("https://example.com/"), actual["issuer"])
            assertEquals(JsonPrimitive("https://example.com/authorize"), actual["authorization_endpoint"])
            assertEquals(JsonPrimitive("https://example.com/token"), actual["token_endpoint"])
            assertEquals(JsonPrimitive("https://example.com/register"), actual["registration_endpoint"])
            assertEquals(JsonPrimitive("https://example.com/endsession"), actual["end_session_endpoint"])
            assertEquals(JsonPrimitive("https://example.com/userinfo"), actual["userinfo_endpoint"])
            assertEquals(buildJsonArray { add(JsonPrimitive("code")); add(JsonPrimitive("token"))}, actual["response_types_supported"])

            assertEquals(JsonPrimitive("https://example.com/jwk"), actual["jwks_uri"])
        }
    }
}
