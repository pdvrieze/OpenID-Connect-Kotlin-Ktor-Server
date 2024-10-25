package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.AuthorizationRequest

/**
 * Authentication representing the request using an OAuth2 Access token.
 */
class OAuth2RequestAuthentication(
    val authorizationRequest: AuthorizationRequest,
    val userAuthentication: SavedUserAuthentication?
) : Authentication {

    override val authorities: Collection<GrantedAuthority> =
        userAuthentication?.authorities ?: authorizationRequest.authorities

    override val isAuthenticated: Boolean
        get() = authorizationRequest.isApproved && (userAuthentication == null || userAuthentication.isAuthenticated)

    override val name: String
        get() = userAuthentication?.name ?: authorizationRequest.clientId

    val isClientOnly: Boolean
        get() = userAuthentication == null
}

