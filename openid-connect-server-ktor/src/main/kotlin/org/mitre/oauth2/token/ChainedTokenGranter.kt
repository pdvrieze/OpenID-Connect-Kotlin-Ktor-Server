package org.mitre.oauth2.token

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

    override val isGrantAllowsRefresh: Boolean
        get() = TODO("not implemented")

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant_type:redelegate"
    }
}
