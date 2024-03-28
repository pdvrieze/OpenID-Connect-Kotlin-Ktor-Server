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
package org.mitre.openid.connect.client.service.impl

import org.apache.http.client.utils.URIBuilder
import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService
import org.springframework.security.authentication.AuthenticationServiceException
import java.net.URISyntaxException
import javax.annotation.PostConstruct
import javax.servlet.http.HttpServletRequest

/**
 *
 * Determines the issuer using an account chooser or other third-party-initiated login
 *
 * @author jricher
 */
class ThirdPartyIssuerService : IssuerService {
    lateinit var accountChooserUrl: String

    var whitelist: Set<String> = HashSet()
    var blacklist: Set<String> = HashSet()

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.IssuerService#getIssuer(javax.servlet.http.HttpServletRequest)
	 */
    override fun getIssuer(request: HttpServletRequest): IssuerServiceResponse {
        // if the issuer is passed in, return that

        val iss = request.getParameter("iss")
        if (! iss.isNullOrEmpty()) {
            if (whitelist.isNotEmpty() && iss !in whitelist) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $iss")
            }

            if (iss in blacklist) {
                throw AuthenticationServiceException("Issuer was in blacklist: $iss")
            }

            return IssuerServiceResponse(iss, request.getParameter("login_hint"), request.getParameter("target_link_uri"))
        } else {
            try {
                // otherwise, need to forward to the account chooser
                val redirectUri = request.requestURL.toString()
                val builder = URIBuilder(accountChooserUrl)

                builder.addParameter("redirect_uri", redirectUri)

                return IssuerServiceResponse(builder.build().toString())
            } catch (e: URISyntaxException) {
                throw AuthenticationServiceException("Account Chooser URL is not valid", e)
            }
        }
    }

    @PostConstruct
    fun afterPropertiesSet() {
        require(::accountChooserUrl.isInitialized && accountChooserUrl.isNotEmpty()) { "Account Chooser URL cannot be null or empty" }
    }
}
