package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.AuthorizationRequest

interface Authentication {
    val authorities: Collection<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

val Authentication.authorizationRequest: AuthorizationRequest?
    get() = when (this) {
        is OAuth2RequestAuthentication -> authorizationRequest
        else -> null
    }
