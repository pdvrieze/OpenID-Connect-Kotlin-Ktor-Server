package org.mitre.oauth2.token

import org.mitre.oauth2.exception.InvalidScopeException
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory

/**
 * @author jricher
 */
class ChainedTokenGranter constructor(// keep down-cast versions so we can get to the right queries
    tokenServices: OAuth2TokenEntityService,
    clientResolver: ClientResolver,
    requestFactory: OAuth2RequestFactory
    // TODO: remove cast to ClientDetails service, but that means inhertence needs to be different
) : AbstractTokenGranter(tokenServices, clientResolver, requestFactory, GRANT_TYPE) {

    override suspend fun getOAuth2Authentication(client: OAuthClientDetails, tokenRequest: TokenRequest): OAuth2RequestAuthentication {
        // read and load up the existing token
        val incomingTokenValue = tokenRequest.requestParameters["token"] ?: throw IllegalArgumentException("Missing token parameter")
        val incomingToken = tokenServices.readAccessToken(incomingTokenValue)

        // check for scoping in the request, can't up-scope with a chained request
        val approvedScopes: Set<String> = incomingToken.scope
        var requestedScopes: Set<String> = tokenRequest.scope ?: HashSet()

        // do a check on the requested scopes -- if they exactly match the client scopes, they were probably shadowed by the token granter
        if (client.scope == requestedScopes) {
            requestedScopes = HashSet()
        }

        // if our scopes are a valid subset of what's allowed, we can continue
        if (!approvedScopes.containsAll(requestedScopes)) {
            throw InvalidScopeException("Invalid scope requested in chained request: ${approvedScopes.joinToString()}", )
        }

        if (requestedScopes.isEmpty()) {
            // if there are no scopes, inherit the original scopes from the token
            tokenRequest.scope = approvedScopes
        } else {
            // if scopes were asked for, give only the subset of scopes requested
            // this allows safe downscoping
            tokenRequest.scope = requestedScopes.intersect(approvedScopes)
        }

        // NOTE: don't revoke the existing access token

        // create a new access token
        val authentication = OAuth2RequestAuthentication(
            oAuth2Request = requestFactory.createAuthorizationRequest(tokenRequest.requestParameters),
            userAuthentication = incomingToken.authenticationHolder.authentication.userAuthentication
        )

        return authentication
    }

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant_type:redelegate"
    }
}
