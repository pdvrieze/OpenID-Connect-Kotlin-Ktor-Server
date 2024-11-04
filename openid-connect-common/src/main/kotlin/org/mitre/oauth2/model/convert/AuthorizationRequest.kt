package org.mitre.oauth2.model.convert

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

/**
 * Object representing a request for authorization (in the authorization endpoint).
 * This request does not have authentication information present.
 */
@Serializable
class AuthorizationRequest(
    @SerialName("authorizationParameters")
    val requestParameters: Map<String, String> = emptyMap(),
    val clientId: String,
    val authorities: Set<GrantedAuthority> = emptySet(),
    @SerialName("approved")
    val isApproved: Boolean = false,
    val scope: Set<String> = emptySet(),
    val resourceIds: Set<String>? = null,
    val redirectUri: String? = null,
    val responseTypes: Set<String>? = null,
    val state: String? = null,
    val requestTime: ISOInstant? = null,
    private val extensionStrings: Map<String, String>? = null,
) {
    @SerialName("extensionStrings")
    val denied: Boolean get() = ! isApproved

    val extensions: Map<String, String> get() = extensionStrings ?: emptyMap()

    val isOpenId get() = SystemScopeService.OPENID_SCOPE in scope

    fun copy(
        requestParameters: Map<String, String> = this.requestParameters,
        clientId: String = this.clientId,
        authorities: Set<GrantedAuthority> = this.authorities,
        isApproved: Boolean = this.isApproved,
        scope: Set<String> = this.scope,
        resourceIds: Set<String>? = this.resourceIds,
        redirectUri: String? = this.redirectUri,
        responseTypes: Set<String>? = this.responseTypes,
        state: String? = this.state,
        requestTime: Instant? = this.requestTime,
        extensionStrings: Map<String, String>? = this.extensionStrings,
    ) : AuthorizationRequest {
        return AuthorizationRequest(
            requestParameters = requestParameters,
            clientId = clientId,
            authorities = authorities,
            isApproved = isApproved,
            scope = scope.toSet(),
            resourceIds = resourceIds?.toSet(),
            redirectUri = redirectUri,
            responseTypes = responseTypes?.toSet(),
            state = state,
            requestTime = requestTime,
            extensionStrings = extensionStrings?.toMap(),
        )
    }
}
