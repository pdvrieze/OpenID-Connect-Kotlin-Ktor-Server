package org.mitre.oauth2.token

import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request

interface TokenGranter {
    val grantType: String

    val isGrantAllowsRefresh: Boolean

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: OAuth2Request,
    ): OAuth2RequestAuthentication {
        return OAuth2RequestAuthentication(request, null)
    }

    suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: OAuth2RequestAuthentication,
        isAllowRefresh: Boolean = isGrantAllowsRefresh,
    ): OAuth2AccessToken

    suspend fun grant(grantType: String, request: OAuth2Request, authenticatedClient: OAuthClientDetails): OAuth2AccessToken
}

