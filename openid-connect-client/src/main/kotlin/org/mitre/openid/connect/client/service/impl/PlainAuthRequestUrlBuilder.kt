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
import io.ktor.server.util.*
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.config.ServerConfiguration

/**
 *
 * Builds an auth request redirect URI with normal query parameters.
 *
 * @author jricher
 */
class PlainAuthRequestUrlBuilder : AuthRequestUrlBuilder {
    override suspend fun buildAuthRequestUrl(
        serverConfig: ServerConfiguration,
        clientConfig: RegisteredClient,
        redirectUri: String,
        nonce: String,
        state: String,
        options: Map<String, String>,
        loginHint: String?
    ): String {
        return url {
            takeFrom(serverConfig.authorizationEndpointUri!!)
            with(parameters) {
                append("response_type", "code")
                append("client_id", clientConfig.clientId!!)
                append("scope", clientConfig.scope?.joinToString(" ")?:"")

                append("redirect_uri", redirectUri)

                append("nonce", nonce)

                append("state", state)

                // Optional parameters:
                for ((key, value) in options) {
                    append(key, value)
                }

                // if there's a login hint, send it
                if (!loginHint.isNullOrEmpty()) {
                    append("login_hint", loginHint)
                }
            }
        }
    }
}
