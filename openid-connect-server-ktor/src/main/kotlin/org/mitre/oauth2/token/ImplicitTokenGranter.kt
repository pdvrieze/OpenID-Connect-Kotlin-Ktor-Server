package org.mitre.oauth2.token

import io.github.pdvrieze.auth.ClientAuthentication
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

class ImplicitTokenGranter(
    tokenService: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "token"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType) {
    override val isGrantAllowsRefresh: Boolean get() = false

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        clientAuth: ClientAuthentication,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest {
        throw UnsupportedOperationException("implicit token granter does not allow creating an authenticated request")
    }
}

