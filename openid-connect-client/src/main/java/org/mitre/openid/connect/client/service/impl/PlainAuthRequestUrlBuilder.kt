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

import com.google.common.base.Joiner
import org.apache.http.client.utils.URIBuilder
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.config.ServerConfiguration
import org.springframework.security.authentication.AuthenticationServiceException
import java.net.URISyntaxException

/**
 *
 * Builds an auth request redirect URI with normal query parameters.
 *
 * @author jricher
 */
class PlainAuthRequestUrlBuilder : AuthRequestUrlBuilder {
    override fun buildAuthRequestUrl(
        serverConfig: ServerConfiguration,
        clientConfig: RegisteredClient,
        redirectUri: String?,
        nonce: String?,
        state: String?,
        options: Map<String, String>,
        loginHint: String?
    ): String {
        try {
            return URIBuilder(serverConfig.authorizationEndpointUri).apply {
                addParameter("response_type", "code")
                addParameter("client_id", clientConfig.clientId)
                addParameter("scope", Joiner.on(" ").join(clientConfig.scope))

                addParameter("redirect_uri", redirectUri)

                addParameter("nonce", nonce)

                addParameter("state", state)

                // Optional parameters:
                for ((key, value) in options) {
                    addParameter(key, value)
                }

                // if there's a login hint, send it
                if (!loginHint.isNullOrEmpty()) {
                    addParameter("login_hint", loginHint)
                }
            }.build().toString()
        } catch (e: URISyntaxException) {
            throw AuthenticationServiceException("Malformed Authorization Endpoint Uri", e)
        }
    }
}
