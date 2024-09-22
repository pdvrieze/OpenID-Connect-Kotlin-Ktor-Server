package org.mitre.oauth2.model

import org.mitre.oauth2.model.convert.OAuth2Request

interface Authentication {
    val authorities: Collection<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

val Authentication.oAuth2Request: OAuth2Request?
    get() = when (this) {
        is OAuth2Authentication -> oAuth2Request
        else -> null
    }
