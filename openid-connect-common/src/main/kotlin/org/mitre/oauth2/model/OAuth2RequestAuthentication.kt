package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.OAuth2Request

/**
 * Authentication representing the request using an OAuth2 Access token.
 */
class OAuth2RequestAuthentication(
    val oAuth2Request: OAuth2Request,
    val userAuthentication: SavedUserAuthentication?
) : Authentication {

    override val authorities: Collection<GrantedAuthority> =
        userAuthentication?.authorities ?: oAuth2Request.authorities

    override val isAuthenticated: Boolean
        get() = oAuth2Request.isApproved && (userAuthentication == null || userAuthentication.isAuthenticated)

    override val name: String
        get() = userAuthentication?.name ?: oAuth2Request.clientId

    val isClientOnly: Boolean
        get() = userAuthentication == null
}

