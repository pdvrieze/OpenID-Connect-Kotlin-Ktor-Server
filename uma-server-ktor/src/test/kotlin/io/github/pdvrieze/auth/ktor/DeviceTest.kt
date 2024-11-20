package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.repository.exposed.DeviceCodeRequestParameters
import io.github.pdvrieze.auth.repository.exposed.DeviceCodeScopes
import io.github.pdvrieze.auth.repository.exposed.DeviceCodes
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.sql.Table
import org.mitre.oauth2.web.DeviceEndpoint
import org.mitre.openid.connect.filter.AuthTokenResponse
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.openid.connect.view.OAuthError
import org.mitre.web.OpenIdSessionStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/** Tests the device endpoint as specified in RFC 8628 */
class DeviceTest: ApiTest(DeviceEndpoint, PlainAuthorizationRequestEndpoint) {

    // TODO add test that verifies an error if the client is not authorized for device grants.
    override val deletableTables: List<Table>
        get() = listOf(DeviceCodeRequestParameters, DeviceCodeScopes, DeviceCodes) + super.deletableTables

    @Test
    fun testInitiateDeviceAuth() = testEndpoint {
        val r = submitUnAuth("/devicecode", parameters {
            append("client_id", clientId)
            append("scope", "scope1")
        })
        val response = r.body<DeviceAuthResponse>()
        assertEquals("https://example.com/device", response.verificationUri)


        val accessRequestResponse = submitClient("/token", parameters {
            append("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
            append("device_code", response.deviceCode)
        }, HttpStatusCode.BadRequest)
        val error = accessRequestResponse.body<OAuthError>()
        assertEquals("authorization_pending", error.errorCode)

    }

    @Test
    fun testUserDeviceFormOnly() = testEndpoint {
//        val deviceAuthResponse = oidJson.decodeFromString<DeviceAuthResponse>(submitUnAuth("/devicecode", parameters {
//            append("client_id", clientId)
//            append("scope", "scope1")
//        }).bodyAsText())

        val r = getUser("/device")
        val sessionCookie = r.setCookie().singleOrNull { it.name == OpenIdSessionStorage.COOKIE_NAME }
        assertNotNull(sessionCookie, "Missing auth session cookie")
        val html = r.bodyAsText()
        val forms = FormInfo(html)
        val verifyForm = forms.single { "/device/verify" in it.action }
        val codeInput = assertNotNull(verifyForm.input("user_code"), "Missing user code input")
        assertEquals("text", codeInput.type)
        val approveInput = assertNotNull(verifyForm.input("approve"))
        assertEquals("submit", approveInput.type)
    }

    @Test
    fun testUserDeviceFormDoesNotAuthorize() {
        val deviceAuthResponse = testEndpoint {
            submitUnAuth("/devicecode", parameters {
                append("client_id", clientId)
                append("scope", "scope1")
            }).body<DeviceAuthResponse>()
        }

        testUserDeviceFormOnly()

        testEndpoint {
            val accessRequestResponse = submitClient("/token", parameters {
                append("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                append("device_code", deviceAuthResponse.deviceCode)
            }, HttpStatusCode.BadRequest)
            val error = accessRequestResponse.body<OAuthError>()
            assertEquals("authorization_pending", error.errorCode)
        }
    }

    @Test
    fun testDeviceAuthenticationNoSession() {
        testEndpoint {
            val deviceReq = submitUnAuth("/devicecode", parameters {
                append("client_id", clientId)
                append("scope", "scope1")
            }).body<DeviceAuthResponse>()

            val sessionCookie = getUser("/device").setCookie()
                .singleOrNull { it.name == OpenIdSessionStorage.COOKIE_NAME }

            submitUser("/device/verify", parameters {

            }, HttpStatusCode.BadRequest) // check that this doesn't work
        }
    }

    @Test
    fun testDeviceAuthentication() {
        testEndpoint {
            val deviceReq = submitUnAuth("/devicecode", parameters {
                append("client_id", clientId)
                append("scope", "scope1")
            }).body<DeviceAuthResponse>()

            val sessionCookie = getUser("/device").setCookie()
                .single { it.name == OpenIdSessionStorage.COOKIE_NAME }

            val submitResp = submitUnAuth("/device/verify", parameters {
                append("user_code", deviceReq.userCode)
                append("approve", "Approve")
            }) {
                headers {
                    append(HttpHeaders.Cookie, renderCookieHeader(sessionCookie))
                }
            }

            val exchangeResp = submitClient("/token", parameters {
                append("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                append("device_code", deviceReq.deviceCode)
                append("client_id", clientId)
            })

            val accessTokenResponse = exchangeResp.body<AuthTokenResponse>()
            assertNotNull(accessTokenResponse)
            assertNotNull(accessTokenResponse.accessToken)
        }
    }

    @Serializable
    data class DeviceAuthResponse(
        @SerialName("device_code")
        val deviceCode: String,
        @SerialName("user_code")
        val userCode: String,
        @SerialName("verification_uri")
        val verificationUri: String,
        @SerialName("verification_uri_complete")
        val verificationUriComplete: String? = null,
        @SerialName("expires_in")
        val expiresIn: Long,
        val interval: Long = 5
    )
}
