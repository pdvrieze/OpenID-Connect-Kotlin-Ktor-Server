package org.mitre.oauth2.model

import org.mitre.oauth2.model.request.AuthorizationRequest

interface Authentication {
    val authorities: Collection<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

val Authentication.authorizationRequest: AuthorizationRequest?
    get() = when (this) {
        is AuthenticatedAuthorizationRequest -> authorizationRequest
        else -> null
    }
