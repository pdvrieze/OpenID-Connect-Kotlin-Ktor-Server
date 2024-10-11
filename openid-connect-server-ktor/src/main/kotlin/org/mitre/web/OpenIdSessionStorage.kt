package org.mitre.web

import io.ktor.server.auth.*
import org.mitre.oauth2.model.convert.OAuth2Request

data class OpenIdSessionStorage(
    val authorizationRequest: OAuth2Request? = null,
    val principal: UserIdPrincipal? = null,
    val redirectUri: String? = null,
    val state: String? = null,
) {

    companion object {
        val COOKIE_NAME: String = "_openid_session"
    }
}
