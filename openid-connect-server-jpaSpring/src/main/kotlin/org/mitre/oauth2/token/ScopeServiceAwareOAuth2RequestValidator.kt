/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package org.mitre.oauth2.token

import org.mitre.oauth2.service.SystemScopeService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.OAuth2RequestValidator
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.stereotype.Component

/**
 *
 * Validates the scopes on a request by comparing them against a client's
 * allowed scopes, but allow custom scopes to function through the system scopes
 *
 * @author jricher
 */
@Component
class ScopeServiceAwareOAuth2RequestValidator : OAuth2RequestValidator {
    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Throws(InvalidScopeException::class)
    private fun validateScope(requestedScopes: Set<String>?, clientScopes: Set<String>?) {
        if (!requestedScopes.isNullOrEmpty()) {
            if (!clientScopes.isNullOrEmpty()) {
                if (!scopeService.scopesMatch(clientScopes, requestedScopes)) {
                    throw InvalidScopeException("Invalid scope; requested:$requestedScopes", clientScopes)
                }
            }
        }
    }

    @Throws(InvalidScopeException::class)
    override fun validateScope(authorizationRequest: AuthorizationRequest, client: ClientDetails) {
        validateScope(authorizationRequest.scope, client.scope)
    }

    @Throws(InvalidScopeException::class)
    override fun validateScope(tokenRequest: TokenRequest, client: ClientDetails) {
        validateScope(tokenRequest.scope, client.scope)
    }
}
