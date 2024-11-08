package org.mitre.oauth2.token

import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

class ClientTokenGranter(
    tokenService: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "client_credentials"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType) {
    override val isGrantAllowsRefresh: Boolean get() = false
}

class RefreshTokenGranter(
    tokenService: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "refresh_token"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType) {
    override val isGrantAllowsRefresh: Boolean get() = true
    override suspend fun grant(
        grantType: String,
        request: AuthorizationRequest,
        authenticatedClient: OAuthClientDetails,
        requestParameters: Map<String, String>,
    ): OAuth2AccessToken {
        return super.grant(grantType, request, authenticatedClient, requestParameters)
    }

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest {
        return super.getOAuth2Authentication(client, request, requestParameters)
    }

    override suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean,
        requestParameters: Map<String, String>,
    ): OAuth2AccessToken {
        val refreshToken = requestParameters["refresh_token"] ?:
            throw OAuth2Exception(OAuthErrorCodes.INVALID_REQUEST)
        return tokenServices.refreshAccessToken(refreshToken, tokenRequest.authorizationRequest)
    }
}
