package org.mitre.oauth2.token

import io.github.pdvrieze.auth.ClientAuthentication
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

/**
 * @author jricher
 */
class ChainedTokenGranter(// keep down-cast versions so we can get to the right queries
    tokenServices: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory
    // TODO: remove cast to ClientDetails service, but that means inhertence needs to be different
) : AbstractTokenGranter(tokenServices, clientResolver, requestFactory, GRANT_TYPE) {

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        clientAuth: ClientAuthentication,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest {
        TODO("not implemented")
    }

    override val isGrantAllowsRefresh: Boolean
        get() = TODO("not implemented")

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant_type:redelegate"
    }
}
