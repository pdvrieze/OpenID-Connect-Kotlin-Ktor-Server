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

import io.github.pdvrieze.openid.spring.fromSpring
import io.github.pdvrieze.openid.spring.toSpring
import kotlinx.coroutines.runBlocking
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter
import org.springframework.stereotype.Component
import org.springframework.security.oauth2.common.OAuth2AccessToken as SpringOAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication as SpringOAuth2Authentication

/**
 * @author jricher
 */
@Component("chainedTokenGranter")
class ChainedTokenGranter @Autowired constructor(// keep down-cast versions so we can get to the right queries
    private val tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientResolver?,
    requestFactory: OAuth2RequestFactory?
    // TODO: remove cast to ClientDetails service, but that means inhertence needs to be different
) : AbstractTokenGranter(null, clientDetailsService as ClientDetailsService, requestFactory, GRANT_TYPE) {

    @Throws(AuthenticationException::class, InvalidTokenException::class)
    override fun getOAuth2Authentication(client: ClientDetails, tokenRequest: TokenRequest): SpringOAuth2Authentication {
        // read and load up the existing token
        val incomingTokenValue = tokenRequest.requestParameters["token"]
        val incomingToken = incomingTokenValue?.let { tokenServices.readAccessToken(it) }

        // check for scoping in the request, can't up-scope with a chained request
        val approvedScopes: Set<String>? = incomingToken?.scope
        var requestedScopes: Set<String> = tokenRequest.scope ?: HashSet()

        // do a check on the requested scopes -- if they exactly match the client scopes, they were probably shadowed by the token granter
        if (client.scope == requestedScopes) {
            requestedScopes = HashSet()
        }

        // if our scopes are a valid subset of what's allowed, we can continue
        if (approvedScopes!!.containsAll(requestedScopes)) {
            if (requestedScopes.isEmpty()) {
                // if there are no scopes, inherit the original scopes from the token
                tokenRequest.setScope(approvedScopes)
            } else {
                // if scopes were asked for, give only the subset of scopes requested
                // this allows safe downscoping
                tokenRequest.setScope(requestedScopes.intersect(approvedScopes))
            }

            // NOTE: don't revoke the existing access token

            // create a new access token
            val authentication =
                OAuth2RequestAuthentication(requestFactory.createOAuth2Request(client, tokenRequest).fromSpring(), incomingToken.authenticationHolder.authentication.userAuthentication)

            return authentication.toSpring()
        } else {
            throw InvalidScopeException("Invalid scope requested in chained request", approvedScopes)
        }
    }

    override fun getAccessToken(client: ClientDetails, tokenRequest: TokenRequest): SpringOAuth2AccessToken = runBlocking {
        tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest).fromSpring(), xxx).toSpring()
    }

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant_type:redelegate"
    }
}
