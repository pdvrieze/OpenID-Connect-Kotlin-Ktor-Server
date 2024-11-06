package org.mitre.oauth2.model

import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.openid.connect.model.convert.ISOInstant

interface AuthenticationHolder {
    fun copy(id: Long?): AuthenticationHolder

    val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
        get() = AuthenticatedAuthorizationRequest(authorizationRequest, userAuth)

    val id: Long?
    val userAuth: SavedUserAuthentication?
    val authorizationRequest: AuthorizationRequest

    val authorities: Set<GrantedAuthority>? get() = authorizationRequest.authorities
    val resourceIds: Set<String>? get() = authorizationRequest.resourceIds
    val isApproved: Boolean get() = authorizationRequest.isApproved
    val redirectUri: String? get() = authorizationRequest.redirectUri
    val responseTypes: Set<String>? get() = authorizationRequest.responseTypes
    val extensions: Map<String, String>? get() = authorizationRequest.authHolderExtensions
    val clientId: String? get() = authorizationRequest.clientId
    val scope: Set<String>? get() = authorizationRequest.scope
    val requestParameters: Map<String, String>? get() = authorizationRequest.requestParameters
    val requestTime: ISOInstant? get() = authorizationRequest.requestTime

    object DUMMY: AuthenticationHolder {
        override val id: Nothing? get() = null
        override val userAuth: Nothing? get() = null
        override fun copy(id: Long?): DUMMY = DUMMY
        override val authorizationRequest: AuthorizationRequest
            get() = throw UnsupportedOperationException()
    }
}
