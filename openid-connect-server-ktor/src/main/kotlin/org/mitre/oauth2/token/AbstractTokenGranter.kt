package org.mitre.oauth2.token

import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

abstract class AbstractTokenGranter(
    protected val tokenServices: OAuth2TokenEntityService,
    protected val clientResolver: ClientResolver,
    protected val requestFactory: OAuth2RequestFactory,
    override val grantType: String,
) : TokenGranter {

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication {
        return getOAuth2Authentication(client, requestFactory.createAuthorizationRequest(tokenRequest.requestParameters))
    }

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        request: OAuth2Request,
    ): OAuth2RequestAuthentication {
        return OAuth2RequestAuthentication(request, null)
    }

    override suspend fun getAccessToken(client: OAuthClientDetails, tokenRequest: TokenRequest): OAuth2AccessToken {
        return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest))
    }

    override suspend fun getAccessToken(client: OAuthClientDetails, tokenRequest: OAuth2Request): OAuth2AccessToken {
        return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest))
    }

    open suspend fun grant(grantType: String, request: OAuth2Request): OAuth2AccessToken {
        check(grantType == this.grantType) { "This granter (${this.grantType}) does not support the requested grant type ($grantType)" }

        val clientId = request.clientId

        val clientDetails = clientResolver.loadClientByClientId(clientId)
            ?: throw IllegalArgumentException("Client not found: $clientId")

        validateGrantType(grantType, clientDetails)

        return getAccessToken(clientDetails, request)
    }

    protected open fun validateGrantType(grantType: String, clientDetails: OAuthClientDetails) {
        if (clientDetails.authorizedGrantTypes.run { isNotEmpty() && !contains(grantType) }) {
            throw InvalidClientException("Invalid grant: $grantType")
        }
    }

}
