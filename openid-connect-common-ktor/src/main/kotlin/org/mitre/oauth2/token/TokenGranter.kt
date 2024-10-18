package org.mitre.oauth2.token

import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails

interface TokenGranter {
    val grantType: String

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: OAuth2RequestAuthentication
    ): OAuth2RequestAuthentication?

    suspend fun getAccessToken(client: OAuthClientDetails, tokenRequest: OAuth2RequestAuthentication): OAuth2AccessToken
}

