package org.mitre.oauth2.token

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

}
