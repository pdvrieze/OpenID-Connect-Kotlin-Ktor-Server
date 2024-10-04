package org.mitre.oauth2.token

import org.mitre.oauth2.exception.InvalidScopeException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.SystemScopeService

/**
 *
 * Validates the scopes on a request by comparing them against a client's
 * allowed scopes, but allow custom scopes to function through the system scopes
 *
 * @author jricher
 */
class ScopeServiceAwareOAuth2RequestValidator(
    var scopeService: SystemScopeService
) {

    private fun validateScope(requestedScopes: Set<String>?, clientScopes: Set<String>?) {
        if (!requestedScopes.isNullOrEmpty()) {
            if (!clientScopes.isNullOrEmpty()) {
                if (!scopeService.scopesMatch(clientScopes, requestedScopes)) {
                    throw InvalidScopeException("Invalid scope; requested: $requestedScopes, client: ${clientScopes.joinToString()}")
                }
            }
        }
    }

    fun validateScope(authorizationRequest: Any?, client: OAuthClientDetails) {
        TODO()
//        validateScope(authorizationRequest.scope, client.scope)
    }

    fun validateScope(tokenRequest: TokenRequest, client: OAuthClientDetails) {
        validateScope(tokenRequest.scope, client.scope)
    }
}
