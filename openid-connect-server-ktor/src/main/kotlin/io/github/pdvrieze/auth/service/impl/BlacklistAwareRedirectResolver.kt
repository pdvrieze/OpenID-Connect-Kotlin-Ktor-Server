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

import io.github.pdvrieze.auth.service.impl.AbstractRedirectResolver
import org.mitre.oauth2.exception.InvalidRequestException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.BlacklistedSiteService

/**
 *
 * A redirect resolver that knows how to check against the blacklisted URIs
 * for forbidden values. Can be configured to do strict string matching also.
 *
 * @author jricher
 */
class BlacklistAwareRedirectResolver(
    val blacklistService: BlacklistedSiteService,
    val config: ConfigurationPropertiesBean
) : AbstractRedirectResolver() {

    /**
     * Set this to true to require exact string matches for all redirect URIs. (Default is false)
     *
     */
    var isStrictMatch: Boolean = true

        get() = config.isHeartMode || field // HEART mode enforces strict matching

    /* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.endpoint.RedirectResolver#resolveRedirect(java.lang.String, org.springframework.security.oauth2.provider.ClientDetails)
	 */
    override fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String {
        val redirect = super.resolveRedirect(requestedRedirect, client)
        if (blacklistService.isBlacklisted(redirect)) {
            // don't let it go through
            throw InvalidRequestException("The supplied redirect_uri is not allowed on this server.")
        } else {
            // not blacklisted, passed the parent test, we're fine
            return redirect
        }
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
