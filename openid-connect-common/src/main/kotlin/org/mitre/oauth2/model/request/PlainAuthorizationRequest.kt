package org.mitre.oauth2.model.request

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.model.convert.ISOInstant

/**
 * Object representing a request for authorization (in the authorization endpoint).
 * This request does not have authentication information present.
 */
@Serializable
class PlainAuthorizationRequest(
    @SerialName("authorizationParameters")
    override val requestParameters: Map<String, String> = emptyMap(),
    override val clientId: String,
    override val authorities: Set<GrantedAuthority> = emptySet(),
    @SerialName("approved")
    override val isApproved: Boolean = false,
    override val scope: Set<String> = emptySet(),
    override val resourceIds: Set<String>? = null,
    override val redirectUri: String? = null,
    override val responseTypes: Set<String>? = null,
    override val state: String? = null,
    override val requestTime: ISOInstant? = null,
    val extensions: Map<String, String> = emptyMap(),
) : AuthorizationRequest {

    val isOpenId get() = SystemScopeService.OPENID_SCOPE in scope

    override val authHolderExtensions: Map<String, String>
        get() = emptyMap()

    override fun builder(): Builder {
        return Builder(this)
    }

    constructor(
        requestParameters: Map<String, String> = emptyMap(),
        clientId: String,
        authorities: Set<GrantedAuthority> = emptySet(),
        isApproved: Boolean = false,
        scope: Set<String> = emptySet(),
        resourceIds: Set<String>? = null,
        redirectUri: String? = null,
        responseTypes: Set<String>? = null,
        state: String? = null,
        requestTime: ISOInstant? = null,
        extensionStrings: Map<String, String>?,
        dummy: Unit = Unit
    ) : this(
        requestParameters = requestParameters,
        clientId = clientId,
        authorities = authorities,
        isApproved = isApproved,
        scope = scope,
        resourceIds = resourceIds,
        redirectUri = redirectUri,
        responseTypes = responseTypes,
        state = state,
        requestTime = requestTime,
        extensions = extensionStrings ?: emptyMap(),
    )

    class Builder(clientId: String): AuthorizationRequest.Builder(clientId) {
        constructor(orig: PlainAuthorizationRequest) : this(orig.clientId) {
            requestParameters = orig.requestParameters
            authorities = orig.authorities
            isApproved = orig.isApproved
            scope = orig.scope
            resourceIds = orig.resourceIds
            redirectUri = orig.redirectUri
            responseTypes = orig.responseTypes
            state = orig.state
            requestTime = orig.requestTime
        }

        override fun build(): PlainAuthorizationRequest {
            return PlainAuthorizationRequest(requestParameters, clientId, authorities, isApproved, scope, resourceIds, redirectUri, responseTypes, state, requestTime)
        }

        override fun setFromExtensions(extensions: Map<String, String>) {
            require(extensions.isEmpty()) { "No extensions expected in plain request" }
        }
    }
}
