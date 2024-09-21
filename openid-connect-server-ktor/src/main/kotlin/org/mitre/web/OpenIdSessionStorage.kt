package org.mitre.web

import org.mitre.oauth2.model.convert.OAuth2Request

data class OpenIdSessionStorage(
    val authorizationRequest: OAuth2Request? = null,
) {
    companion object {
        val COOKIE_NAME: String = "_openid_session"
    }
}
