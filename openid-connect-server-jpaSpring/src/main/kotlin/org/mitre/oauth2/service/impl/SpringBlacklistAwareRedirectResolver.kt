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
package org.mitre.oauth2.service.impl

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.IBlacklistAwareRedirectResolver
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.client.BaseClientDetails
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver
import org.springframework.stereotype.Component

/**
 *
 * A redirect resolver that knows how to check against the blacklisted URIs
 * for forbidden values. Can be configured to do strict string matching also.
 *
 * @author jricher
 */
@Component("blacklistAwareRedirectResolver")
class SpringBlacklistAwareRedirectResolver : DefaultRedirectResolver(), IBlacklistAwareRedirectResolver {
    @Autowired
    private lateinit var blacklistService: BlacklistedSiteService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    /**
     * Set this to true to require exact string matches for all redirect URIs. (Default is false)
     *
     */
    override var isStrictMatch: Boolean = true

        get() = config.isHeartMode || field // HEART mode enforces strict matching

    /* (non-Javadoc)
         * @see org.springframework.security.oauth2.provider.endpoint.RedirectResolver#resolveRedirect(java.lang.String, org.springframework.security.oauth2.provider.ClientDetails)
         */
    @Throws(OAuth2Exception::class)
    override fun resolveRedirect(requestedRedirect: String, client: ClientDetails): String {
        val redirect = super.resolveRedirect(requestedRedirect, client)
        if (blacklistService.isBlacklisted(redirect)) {
            // don't let it go through
            throw InvalidRequestException("The supplied redirect_uri is not allowed on this server.")
        } else {
            // not blacklisted, passed the parent test, we're fine
            return redirect
        }
    }

    override fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String {
        val clientMapping = BaseClientDetails(
            client.clientId,
            client.resourceIds.joinToString(),
            client.scope?.joinToString(),
            client.authorizedGrantTypes.joinToString(),
            client.redirectUris.joinToString()
        )
        return resolveRedirect(requestedRedirect, clientMapping)
//        return resolveRedirect(requestedRedirect, client.toSpring())
    }

    /* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver#redirectMatches(java.lang.String, java.lang.String)
	 */
    public override fun redirectMatches(requestedRedirect: String, redirectUri: String): Boolean {
        return when {
            isStrictMatch ->
                // we're doing a strict string match for all clients
                requestedRedirect == redirectUri

            else ->
                // otherwise do the prefix-match from the library
                super.redirectMatches(requestedRedirect, redirectUri)

        }
    }
}
