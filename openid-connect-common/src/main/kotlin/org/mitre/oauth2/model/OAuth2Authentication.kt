package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.OAuth2Request

class OAuth2Authentication(
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
