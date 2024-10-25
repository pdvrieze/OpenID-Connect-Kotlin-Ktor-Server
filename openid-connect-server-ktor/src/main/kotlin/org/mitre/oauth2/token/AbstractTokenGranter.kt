package org.mitre.oauth2.token

import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

abstract class AbstractTokenGranter(
    protected val tokenServices: OAuth2TokenEntityService,
    protected val clientResolver: ClientResolver,
    protected val requestFactory: OAuth2RequestFactory,
    override val grantType: String,
) : TokenGranter {

    abstract override val isGrantAllowsRefresh: Boolean

    override suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean,
    ): OAuth2AccessToken {
        return tokenServices.createAccessToken(tokenRequest, isAllowRefresh)
    }

    override suspend fun grant(grantType: String, request: AuthorizationRequest, authenticatedClient: OAuthClientDetails): OAuth2AccessToken {
        check(grantType == this.grantType) { "This granter (${this.grantType}) does not support the requested grant type ($grantType)" }

        val clientId = request.clientId

        val clientDetails = clientResolver.loadClientByClientId(clientId)
            ?: throw IllegalArgumentException("Client not found: $clientId")

        validateGrantType(grantType, clientDetails)

        val authRequest = getOAuth2Authentication(clientDetails, request)
        
        return getAccessToken(clientDetails, authRequest, clientDetails.isAllowRefresh && isGrantAllowsRefresh)
    }

    protected open fun validateGrantType(grantType: String, clientDetails: OAuthClientDetails) {
        if (clientDetails.authorizedGrantTypes.run { isNotEmpty() && !contains(grantType) }) {
            throw InvalidClientException("Invalid grant: $grantType")
        }
    }

}
