package org.mitre.oauth2.web

import org.mitre.oauth2.model.Authentication

/**
 *
 * Utility class to enforce OAuth scopes in authenticated requests.
 *
 * @author jricher
 */
object AuthenticationUtilities {
    /**
     * Makes sure the authentication contains the given scope, throws an exception otherwise
     * @param auth the authentication object to check
     * @param scope the scope to look for
     * @throws InsufficientScopeException if the authentication does not contain that scope
     */
    @JvmStatic
    fun ensureOAuthScope(auth: Authentication, scope: String) {
        TODO("Determine the right way to do this with ktor")
        // if auth is OAuth, make sure we've got the right scope
/*
        if (auth is org.springframework.security.oauth2.provider.OAuth2Authentication) {
            val reqScope = auth.oAuth2Request.scope
            if (reqScope == null || scope !in reqScope) {
                throw org.springframework.security.oauth2.common.exceptions.InsufficientScopeException("Insufficient scope", setOf(scope))
            }
        }
*/
    }

    /**
     * Check to see if the given auth object has ROLE_ADMIN assigned to it or not
     */
    fun isAdmin(auth: Authentication): Boolean {
        return auth.authorities.any { it.authority == "ROLE_ADMIN" }
    }


    fun hasRole(auth: Authentication, role: String): Boolean {
        return auth.authorities.any { it.authority == role }
    }
}
