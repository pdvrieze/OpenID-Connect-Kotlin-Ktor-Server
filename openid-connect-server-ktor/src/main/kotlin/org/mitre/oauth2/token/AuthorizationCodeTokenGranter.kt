package org.mitre.oauth2.token

import io.github.pdvrieze.auth.ClientAuthentication
import org.mitre.oauth2.exception.OAuth2Exception
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2AuthorizationCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

class AuthorizationCodeTokenGranter(
    tokenService: OAuth2TokenEntityService,
    private val authorizationCodeService: OAuth2AuthorizationCodeService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "authorization_code"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType) {
    override val isGrantAllowsRefresh: Boolean get() = true

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        clientAuth: ClientAuthentication,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest {
        val code = requestParameters["code"] ?: throw OAuth2Exception(OAuthErrorCodes.INVALID_REQUEST)

        val authenticatedRequest = authorizationCodeService.consumeAuthorizationCode(code)
        if (authenticatedRequest.authorizationRequest.redirectUri != request.redirectUri)
            throw OAuth2Exception(OAuthErrorCodes.INVALID_REQUEST)
        return authenticatedRequest
    }
}

