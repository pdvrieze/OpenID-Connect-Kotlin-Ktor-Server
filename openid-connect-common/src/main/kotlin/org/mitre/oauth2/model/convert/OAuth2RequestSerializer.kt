package org.mitre.oauth2.model.convert

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.GrantedAuthority

@Serializable
class OAuth2Request(
    @SerialName("authorizationParameters")
    val requestParameters: Map<String, String> = emptyMap(),
    val clientId: String,
    val authorities: Set<GrantedAuthority> = emptySet(),
    @SerialName("approved")
    val isApproved: Boolean = false,
    val scope: Set<String>? = null,
    val resourceIds: Set<String>? = null,
    val redirectUri: String? = null,
    val responseTypes: Set<String>? = null,
    @SerialName("extensionStrings")
    val extensionStrings: Map<String, String>? = null,
    val approvalParameters: JsonElement? = null,
) {
    val denied: Boolean get() = ! isApproved
}



typealias KXS_OAuth2Request = OAuth2Request

