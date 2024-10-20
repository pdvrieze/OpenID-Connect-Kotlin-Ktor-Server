package org.mitre.oauth2.token

import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

class ImplicitTokenGranter(
    tokenService: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    grantType: String = "token"
) : AbstractTokenGranter(tokenService, clientResolver, requestFactory, grantType)
