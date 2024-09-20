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
    val scope: Set<String> = emptySet(),
    val resourceIds: Set<String>? = null,
    val redirectUri: String/*? = null*/,
    val responseTypes: Set<String>? = null,
    @SerialName("extensionStrings")
    val extensionStrings: Map<String, String>? = null,
    val approvalParameters: JsonElement? = null,
) {
    val denied: Boolean get() = ! isApproved
    val extensions: Map<String, String> get() = extensionStrings ?: emptyMap()

    val state by extensions

    fun copy(
        requestParameters: Map<String, String> = this.requestParameters,
        clientId: String = this.clientId,
        authorities: Set<GrantedAuthority> = this.authorities,
        isApproved: Boolean = this.isApproved,
        scope: Set<String> = emptySet(),
        resourceIds: Set<String>? = null,
        redirectUri: String/*? = null*/,
        responseTypes: Set<String>? = null,
        extensionStrings: Map<String, String>? = null,
        approvalParameters: JsonElement? = null,
    ) : OAuth2Request {
        return OAuth2Request(
            requestParameters = requestParameters,
            clientId = clientId,
            authorities = authorities,
            isApproved = isApproved,
            scope = scope,
            resourceIds = resourceIds,
            redirectUri = redirectUri,
            responseTypes = responseTypes,
            extensionStrings = extensionStrings,
            approvalParameters = approvalParameters,
        )
    }
}



typealias KXS_OAuth2Request = OAuth2Request

