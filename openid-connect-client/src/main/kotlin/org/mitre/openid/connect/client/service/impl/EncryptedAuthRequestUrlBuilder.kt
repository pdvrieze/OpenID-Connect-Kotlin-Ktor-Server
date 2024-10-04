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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.http.*
import io.ktor.server.util.*
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder
import org.mitre.openid.connect.config.ServerConfiguration
import org.springframework.security.authentication.AuthenticationServiceException
import java.net.URISyntaxException

/**
 * @author jricher
 */
class EncryptedAuthRequestUrlBuilder : AuthRequestUrlBuilder {
    lateinit var encrypterService: JWKSetCacheService

    var alg: JWEAlgorithm? = null
    var enc: EncryptionMethod? = null


    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.AuthRequestUrlBuilder#buildAuthRequestUrl(org.mitre.openid.connect.config.ServerConfiguration, org.mitre.oauth2.model.RegisteredClient, java.lang.String, java.lang.String, java.lang.String, java.util.Map)
	 */
    override suspend fun buildAuthRequestUrl(
        serverConfig: ServerConfiguration,
        clientConfig: RegisteredClient,
        redirectUri: String,
        nonce: String,
        state: String,
        options: Map<String, String>,
        loginHint: String?
    ): String {
        // create our signed JWT for the request object

        val claims = JWTClaimsSet.Builder()

        //set parameters to JwtClaims
        claims.claim("response_type", "code")
        claims.claim("client_id", clientConfig.clientId)
        claims.claim("scope", clientConfig.scope?.joinToString(" "))

        // build our redirect URI
        claims.claim("redirect_uri", redirectUri)

        // this comes back in the id token
        claims.claim("nonce", nonce)

        // this comes back in the auth request return
        claims.claim("state", state)

        // Optional parameters
        for ((key, value) in options) {
            claims.claim(key, value)
        }

        // if there's a login hint, send it
        if (!loginHint.isNullOrEmpty()) {
            claims.claim("login_hint", loginHint)
        }

        val jwt = EncryptedJWT(JWEHeader(alg, enc), claims.build())

        val encryptor = encrypterService.getEncrypter(serverConfig.jwksUri)!!

        encryptor.encryptJwt(jwt)

        try {

            // build out the URI
            return url {
                takeFrom(serverConfig.authorizationEndpointUri!!)
                parameters.append("request", jwt.serialize())
            }
        } catch (e: URISyntaxException) {
            throw AuthenticationServiceException("Malformed Authorization Endpoint Uri", e)
        }
    }
}
