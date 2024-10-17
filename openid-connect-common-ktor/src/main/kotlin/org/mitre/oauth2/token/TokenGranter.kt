package org.mitre.oauth2.token

import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request

interface TokenGranter {
    val grantType: String

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication?

    suspend fun getAccessToken(client: OAuthClientDetails, tokenRequest: TokenRequest): OAuth2AccessToken

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: OAuth2Request
    ): OAuth2RequestAuthentication?

    suspend fun getAccessToken(client: OAuthClientDetails, tokenRequest: OAuth2Request): OAuth2AccessToken
}

