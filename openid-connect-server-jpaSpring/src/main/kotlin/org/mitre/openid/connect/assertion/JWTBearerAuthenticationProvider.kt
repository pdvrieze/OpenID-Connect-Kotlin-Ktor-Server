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
package org.mitre.openid.connect.assertion

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.util.getLogger
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import java.text.ParseException
import java.util.*

/**
 * @author jricher
 *
 * @property validators map of verifiers, load keys for clients
 * @property timeSkewAllowance Allow for time sync issues by having a window of X seconds.
 */
class JWTBearerAuthenticationProvider(
    private var validators: ClientKeyCacheService,
    private var clientService: ClientDetailsEntityService,
    private var config: ConfigurationPropertiesBean,
    private val timeSkewAllowance: Int = 300,
) {

    /**
     * Try to validate the client credentials by parsing and validating the JWT.
     */
    suspend fun authenticate(authentication: Authentication): Authentication {
        val jwtAuth = authentication as JWTBearerAssertionAuthenticationToken


        try {
            val client = checkNotNull(clientService.loadClientByClientId(jwtAuth.name))

            val jwt = jwtAuth.jwt
            val jwtClaims = jwt?.jwtClaimsSet

            if (jwt !is SignedJWT) {
                throw AuthenticationServiceException("Unsupported JWT type: ${jwt?.javaClass?.name}")
            }

            // check the signature with nimbus
            val jws = jwt

            val alg = jws.header.algorithm

            val tokenEndpointAuthSigningAlg = client.tokenEndpointAuthSigningAlg?.let {
                if(it != alg) {
                    throw AuthenticationServiceException(
                        "Client's registered token endpoint signing algorithm ($it) " +
                                "does not match token's actual algorithm (${alg.name})"
                    )
                }
            }

            if (client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod == AuthMethod.NONE || client.tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC || client.tokenEndpointAuthMethod == AuthMethod.SECRET_POST) {
                // this client doesn't support this type of authentication

                throw AuthenticationServiceException("Client does not support this authentication method.")
            } else if ((client.tokenEndpointAuthMethod == AuthMethod.PRIVATE_KEY &&
                        (alg == JWSAlgorithm.RS256 || alg == JWSAlgorithm.RS384 || alg == JWSAlgorithm.RS512 || alg == JWSAlgorithm.ES256 || alg == JWSAlgorithm.ES384 || alg == JWSAlgorithm.ES512 || alg == JWSAlgorithm.PS256 || alg == JWSAlgorithm.PS384 || alg == JWSAlgorithm.PS512))
                || (client.tokenEndpointAuthMethod == AuthMethod.SECRET_JWT &&
                        (alg == JWSAlgorithm.HS256 || alg == JWSAlgorithm.HS384 || alg == JWSAlgorithm.HS512))
            ) {
                // double-check the method is asymmetrical if we're in HEART mode

                if (config.isHeartMode && client.tokenEndpointAuthMethod != AuthMethod.PRIVATE_KEY) {
                    throw AuthenticationServiceException("[HEART mode] Invalid authentication method")
                }

                val validator = validators.getValidator(client, alg)
                    ?: throw AuthenticationServiceException("Unable to create signature validator for client $client and algorithm $alg")

                if (!validator.validateSignature(jws)) {
                    throw AuthenticationServiceException("Signature did not validate for presented JWT authentication.")
                }
            } else {
                throw AuthenticationServiceException("Unable to create signature validator for method ${client.tokenEndpointAuthMethod} and algorithm $alg")
            }

            // check the issuer
            if (jwtClaims?.issuer == null) {
                throw AuthenticationServiceException("Assertion Token Issuer is null")
            } else if (jwtClaims.issuer != client.clientId) {
                throw AuthenticationServiceException("Issuers do not match, expected ${client.clientId} got ${jwtClaims.issuer}")
            }

            // check expiration
            if (jwtClaims.expirationTime == null) {
                throw AuthenticationServiceException("Assertion Token does not have required expiration claim")
            } else {
                // it's not null, see if it's expired
                val now = Date(System.currentTimeMillis() - (timeSkewAllowance * 1000))
                if (now.after(jwtClaims.expirationTime)) {
                    throw AuthenticationServiceException("Assertion Token is expired: ${jwtClaims.expirationTime}")
                }
            }

            // check not before
            if (jwtClaims.notBeforeTime != null) {
                val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                if (now.before(jwtClaims.notBeforeTime)) {
                    throw AuthenticationServiceException("Assertion Token not valid untill: ${jwtClaims.notBeforeTime}")
                }
            }

            // check issued at
            if (jwtClaims.issueTime != null) {
                // since it's not null, see if it was issued in the future
                val now = Date(System.currentTimeMillis() + (timeSkewAllowance * 1000))
                if (now.before(jwtClaims.issueTime)) {
                    throw AuthenticationServiceException("Assertion Token was issued in the future: " + jwtClaims.issueTime)
                }
            }

            // check audience
            if (jwtClaims.audience == null) {
                throw AuthenticationServiceException("Assertion token audience is null")
            } else if (!(jwtClaims.audience.contains(config.issuer) || jwtClaims.audience.contains("${config.issuer}token"))) {
                throw AuthenticationServiceException("Audience does not match, expected ${config.issuer} or ${config.issuer + "token"} got ${jwtClaims.audience}")
            }

            // IFF we managed to get all the way down here, the token is valid

            // add in the ROLE_CLIENT authority
            val authorities: MutableSet<GrantedAuthority> = HashSet(client.authorities)
            authorities.add(GrantedAuthority.ROLE_CLIENT)

            return JWTBearerAssertionAuthenticationToken(jwt, authorities)
        } catch (e: InvalidClientException) {
            throw UsernameNotFoundException("Could not find client: " + jwtAuth.name)
        } catch (e: ParseException) {
            logger.error("Failure during authentication, error was: ", e)

            throw AuthenticationServiceException("Invalid JWT format")
        }
    }

    /**
     * We support [JWTBearerAssertionAuthenticationToken]s only.
     */
    fun supports(authentication: Class<*>): Boolean {
        return (JWTBearerAssertionAuthenticationToken::class.java.isAssignableFrom(authentication))
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<JWTBearerAuthenticationProvider>()

    }
}
