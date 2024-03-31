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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.apache.http.client.utils.URIBuilder
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.config.ServerConfiguration
import org.springframework.security.authentication.AuthenticationServiceException
import java.net.URISyntaxException

/**
 * @author jricher
 */
class SignedAuthRequestUrlBuilder : AuthRequestUrlBuilder {
    lateinit var signingAndValidationService: JWTSigningAndValidationService

    override fun buildAuthRequestUrl(
        serverConfig: ServerConfiguration,
        clientConfig: RegisteredClient,
        redirectUri: String?,
        nonce: String?,
        state: String?,
        options: Map<String, String>,
        loginHint: String?
    ): String {
        // create our signed JWT for the request object

        val claims = JWTClaimsSet.Builder().apply {
            //set parameters to JwtClaims
            claim("response_type", "code")
            claim("client_id", clientConfig.clientId)
            claim("scope", clientConfig.scope?.joinToString(" "))

            // build our redirect URI
            claim("redirect_uri", redirectUri)

            // this comes back in the id token
            claim("nonce", nonce)

            // this comes back in the auth request return
            claim("state", state)

            // Optional parameters
            for ((key, value) in options) {
                claim(key, value)
            }

            // if there's a login hint, send it
            if (!loginHint.isNullOrEmpty()) {
                claim("login_hint", loginHint)
            }
        }.build()



        val alg = clientConfig.requestObjectSigningAlg
            ?: signingAndValidationService.defaultSigningAlgorithm

        val jwt = SignedJWT(JWSHeader(alg), claims)

        signingAndValidationService.signJwt(jwt, alg!!)

        try {
            val uriBuilder = URIBuilder(serverConfig.authorizationEndpointUri)
            uriBuilder.addParameter("request", jwt.serialize())

            // build out the URI
            return uriBuilder.build().toString()
        } catch (e: URISyntaxException) {
            throw AuthenticationServiceException("Malformed Authorization Endpoint Uri", e)
        }
    }
}
