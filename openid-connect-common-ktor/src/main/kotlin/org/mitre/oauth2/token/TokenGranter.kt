package org.mitre.oauth2.token

import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest

interface TokenGranter {
    val grantType: String

    val isGrantAllowsRefresh: Boolean

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: AuthorizationRequest,
    ): AuthenticatedAuthorizationRequest {
        return AuthenticatedAuthorizationRequest(request, null)
    }

    suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean = isGrantAllowsRefresh,
    ): OAuth2AccessToken

    suspend fun grant(grantType: String, request: AuthorizationRequest, authenticatedClient: OAuthClientDetails): OAuth2AccessToken
}

