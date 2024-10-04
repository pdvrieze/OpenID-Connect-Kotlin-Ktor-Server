package org.mitre.oauth2.token

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

abstract class AbstractTokenGranter(
    protected val tokenServices: OAuth2TokenEntityService,
    protected val clientResolver: ClientResolver?,
    protected val requestFactory: OAuth2RequestFactory,
    protected val grantType: String,
) {

    open suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication? {
        val storedOAuth2Request = requestFactory.createAuthorizationRequest(tokenRequest.requestParameters)
        return OAuth2RequestAuthentication(storedOAuth2Request, null)
    }

    open suspend fun getAccessToken(client: ClientDetailsEntity, tokenRequest: TokenRequest): OAuth2AccessToken? {
        return getOAuth2Authentication(client, tokenRequest)?.let { a -> tokenServices.createAccessToken(a) }
    }
}
