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
package org.mitre.openid.connect.token

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.TokenEnhancer
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.util.getLogger
import java.util.*

abstract class ConnectTokenEnhancer: TokenEnhancer {

    abstract val clientService: ClientDetailsEntityService
    abstract val configBean: ConfigurationPropertiesBean
    abstract val jwtService: JWTSigningAndValidationService
    abstract val userInfoService: UserInfoService
    abstract val connectTokenService: OIDCTokenService

    override suspend fun enhance(accessToken: OAuth2AccessToken.Builder, authentication: OAuth2RequestAuthentication) {
        val originalAuthRequest = authentication.authorizationRequest

        val clientId = originalAuthRequest.clientId
        val client = checkNotNull(clientService.loadClientByClientId(clientId)) { "Missing client ${clientId}" }
        val hasOpenIdScope = originalAuthRequest.scope.contains(SystemScopeService.OPENID_SCOPE)

        val builder = JWTClaimsSet.Builder()
            .claim("azp", clientId)
            .issuer(configBean.issuer)
            .issueTime(Date())
            .expirationTime(accessToken.expiration)
            .subject(authentication.name)
            .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it

        if (!hasOpenIdScope) builder.claim("typ", "at+jwt")

        // TODO set "typ: at+jwt" for OAuth access tokens (but not openid connect)

        val audience = authentication.authorizationRequest.extensionStrings?.get("aud")
        if (!audience.isNullOrEmpty()) {
            builder.audience(listOf(audience))
        }

        addCustomAccessTokenClaims(builder, accessToken, authentication)

        val claims = builder.build()

        val signingAlg = jwtService.defaultSigningAlgorithm
        val header = JWSHeader.Builder(signingAlg)
            .keyID(jwtService.defaultSignerKeyId)
            .build()

        val signed = SignedJWT(header, claims)

        jwtService.signJwt(signed)

        accessToken.jwt = signed

        /**
         * Authorization request scope MUST include "openid" in OIDC, but access token request
         * may or may not include the scope parameter. As long as the AuthorizationRequest
         * has the proper scope, we can consider this a valid OpenID Connect request. Otherwise,
         * we consider it to be a vanilla OAuth2 request.
         *
         * Also, there must be a user authentication involved in the request for it to be considered
         * OIDC and not OAuth, so we check for that as well.
         */
        if (hasOpenIdScope && !authentication.isClientOnly) {
            val username = authentication.name
            val userInfo = userInfoService.getByUsernameAndClientId(username, clientId)

            if (userInfo != null) {
                val idToken = connectTokenService.createIdToken(
                    client,
                    originalAuthRequest, claims.issueTime,
                    userInfo.subject,
                    accessToken
                )

                // attach the id token to the parent access token
                accessToken.setIdToken(idToken)
            } else {
                // can't create an id token if we can't find the user
                logger.warn("Request for ID token when no user is present.")
            }
        }

    }

    /**
     * Hook for subclasses that allows adding custom claims to the JWT that will be used as access token.
     * @param builder the builder holding the current claims
     * @param token the un-enhanced token
     * @param authentication current authentication
     */
    protected open fun addCustomAccessTokenClaims(
        builder: JWTClaimsSet.Builder, token: OAuth2AccessToken.Builder,
        authentication: OAuth2RequestAuthentication?
    ) {
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<ConnectTokenEnhancer>()
    }

}

