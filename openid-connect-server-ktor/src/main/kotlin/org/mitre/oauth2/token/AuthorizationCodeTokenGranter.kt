package org.mitre.oauth2.token

import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.exception.InvalidRequestException
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2AuthorizationCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.RedirectResolver
import org.mitre.openid.connect.request.OAuth2RequestFactory

class AuthorizationCodeTokenGranter(
    tokenService: OAuth2TokenEntityService,
    private val authorizationCodeService: OAuth2AuthorizationCodeService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "authorization_code"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType) {

    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication {
        val params = tokenRequest.requestParameters
        val redirectUri = params["redirect_uri"]
        val authorizationCode = params["code"] ?: throw InvalidRequestException("Missing authorization code")

        val storedAuth = authorizationCodeService.consumeAuthorizationCode(authorizationCode)
//            ?: throw InvalidRequestException("Invalid authorization code: $authorizationCode")

        val pendingRequest = storedAuth.oAuth2Request

        val pendingRedirectUri = pendingRequest.redirectUri

        if ((redirectUri != null || pendingRedirectUri != null ) && pendingRedirectUri != redirectUri) {
            throw RedirectResolver.RedirectMismatchException("Redirect uri mismatch")
        }

        if (client.clientId!! != pendingRequest.clientId)
            throw InvalidClientException("Client id mismatch")

        val combinedParams = pendingRequest.requestParameters.toMutableMap()
        for ((key, value) in params.entries()) {
            combinedParams[key] = value.first()
        }

        val finalRequest = pendingRequest.copy(combinedParams)

        val userAuth = storedAuth.userAuthentication
        return OAuth2RequestAuthentication(finalRequest, userAuth)
    }
}
