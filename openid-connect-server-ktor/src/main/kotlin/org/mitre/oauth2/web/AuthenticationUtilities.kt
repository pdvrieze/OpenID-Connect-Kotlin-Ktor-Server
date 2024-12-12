package org.mitre.oauth2.web

import io.github.pdvrieze.auth.Authentication
import io.ktor.server.auth.*
import org.mitre.oauth2.exception.InsufficientScopeException
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.model.GrantedAuthority

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
    fun ensureOAuthScope(auth: OldAuthentication, scope: String) {
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

    @JvmStatic
    fun ensureOAuthScope(auth: Authentication, scope: String) {
        if (! auth.hasScope(scope)) {
            throw InsufficientScopeException("Insufficient scope ($scope) for auth: $auth")
        }
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
    fun isAdmin(auth: OldAuthentication?): Boolean {
        return (auth ?: return false).authorities.any { it == GrantedAuthority.ROLE_ADMIN }
    }

    /**
     * Check to see if the given auth object has ROLE_ADMIN assigned to it or not
     */
    fun isAdmin(auth: Authentication?): Boolean {
        return (auth ?: return false).authorities.orEmpty().any { it == GrantedAuthority.ROLE_ADMIN }
    }


    fun hasRole(auth: OldAuthentication?, role: GrantedAuthority): Boolean {
        return (auth ?: return false).authorities.any { it == role }
    }

    fun hasRole(auth: Authentication?, role: GrantedAuthority): Boolean {
        return (auth ?: return false).authorities.orEmpty().any { it == role }
    }
}
