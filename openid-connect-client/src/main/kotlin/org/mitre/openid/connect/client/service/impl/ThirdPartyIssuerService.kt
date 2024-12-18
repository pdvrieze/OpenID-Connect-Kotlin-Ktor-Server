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

import io.ktor.http.*
import org.mitre.openid.connect.client.AuthenticationServiceException
import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService
import java.net.URISyntaxException

/**
 *
 * Determines the issuer using an account chooser or other third-party-initiated login
 *
 * @author jricher
 */
class ThirdPartyIssuerService(var accountChooserUrl: String) : IssuerService {

    var whitelist: Set<String> = HashSet()
    var blacklist: Set<String> = HashSet()

    override suspend fun getIssuer(requestParams: Map<String, List<String>>, requestUrl: String): IssuerServiceResponse {
        // if the issuer is passed in, return that

        val iss: String? = requestParams["iss"]?.firstOrNull()
        if (! iss.isNullOrEmpty()) {
            if (whitelist.isNotEmpty() && iss !in whitelist) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $iss")
            }

            if (iss in blacklist) {
                throw AuthenticationServiceException("Issuer was in blacklist: $iss")
            }

            return IssuerServiceResponse(iss, requestParams["login_hint"]?.firstOrNull(), requestParams["target_link_uri"]?.firstOrNull())
        } else {
            try {
                // otherwise, need to forward to the account chooser
                val uri = URLBuilder(accountChooserUrl).apply {
                    parameters.append("redirect_uri", requestUrl)
                }.build().apply { toURI() }

                return IssuerServiceResponse(uri.toString())
            } catch (e: URISyntaxException) {
                throw AuthenticationServiceException("Account Chooser URL is not valid", e)
            }
        }
    }

    init {
        require(accountChooserUrl.isNotEmpty()) { "Account Chooser URL cannot be null or empty" }
    }
}
