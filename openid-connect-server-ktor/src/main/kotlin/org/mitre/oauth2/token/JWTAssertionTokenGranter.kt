package org.mitre.oauth2.token

import io.github.pdvrieze.auth.ClientAuthentication
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

/**
 * @author jricher
 */
class JWTAssertionTokenGranter(
    tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientDetailsEntityService,
    requestFactory: OAuth2RequestFactory,
    private val validator: AssertionValidator,
    private val assertionFactory: AssertionOAuth2RequestFactory
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, grantType) {
    override val isGrantAllowsRefresh: Boolean
        get() = TODO("Unclear grant type")

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        clientAuth: ClientAuthentication,
        request: AuthorizationRequest,
        requestParameters: Map<String, String>,
    ): AuthenticatedAuthorizationRequest {
        TODO("not implemented")
    }

    companion object {
        val logger = org.mitre.util.getLogger<JWTAssertionTokenGranter>()
        private const val grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    }
}
