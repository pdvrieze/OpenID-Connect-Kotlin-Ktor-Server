/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.oauth2.web

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException
import org.springframework.security.oauth2.provider.OAuth2Authentication

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
    fun ensureOAuthScope(auth: Authentication?, scope: String) {
        // if auth is OAuth, make sure we've got the right scope
        if (auth is OAuth2Authentication) {
            val reqScope = auth.oAuth2Request.scope
            if (reqScope == null || scope !in reqScope) {
                throw InsufficientScopeException("Insufficient scope", setOf(scope))
            }
        }
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
