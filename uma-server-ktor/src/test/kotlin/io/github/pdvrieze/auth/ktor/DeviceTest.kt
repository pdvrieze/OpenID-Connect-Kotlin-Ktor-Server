package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.repository.exposed.DeviceCodeRequestParameters
import io.github.pdvrieze.auth.repository.exposed.DeviceCodeScopes
import io.github.pdvrieze.auth.repository.exposed.DeviceCodes
import io.ktor.client.call.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.jetbrains.exposed.sql.Table
import org.mitre.oauth2.web.DeviceEndpoint
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.openid.connect.view.OAuthError
import org.mitre.util.oidJson
import kotlin.test.Test
import kotlin.test.assertEquals

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
    fun testUserDevice() = testEndpoint {
        val deviceAuthResponse = oidJson.decodeFromString<DeviceAuthResponse>(submitUnAuth("/devicecode", parameters {
            append("client_id", clientId)
            append("scope", "scope1")
        }).bodyAsText())

        val r = getUser("/device")
        val html = r.bodyAsText()

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
