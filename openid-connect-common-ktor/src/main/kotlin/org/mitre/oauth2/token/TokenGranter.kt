package org.mitre.oauth2.token

import io.github.pdvrieze.auth.ClientAuthentication
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest

interface TokenGranter {
    val grantType: String

    val isGrantAllowsRefresh: Boolean

    suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        clientAuth: ClientAuthentication,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest /*{
        return AuthenticatedAuthorizationRequest(request, null)
    }*/

    suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean = isGrantAllowsRefresh,
        requestParameters: Map<String, String>,
    ): OAuth2AccessToken

    suspend fun grant(
        grantType: String,
        request: AuthorizationRequest,
        clientAuth: ClientAuthentication,
        authenticatedClient: OAuthClientDetails,
        requestParameters: Map<String, String>
    ): OAuth2AccessToken
}

