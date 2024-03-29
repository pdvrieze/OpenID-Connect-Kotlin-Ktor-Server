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
package org.mitre.openid.connect.service.impl

import com.google.common.base.Strings
import com.google.common.collect.Lists
import com.google.common.collect.Maps
import com.google.common.collect.Sets
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.util.IdTokenHashUtils
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.stereotype.Service
import java.util.*

/**
 * Default implementation of service to create specialty OpenID Connect tokens.
 *
 * @author Amanda Anganes
 */
@Service
open class DefaultOIDCTokenService : OIDCTokenService {
    @Autowired
    lateinit var jwtService: JWTSigningAndValidationService

    @Autowired
    lateinit var authenticationHolderRepository: AuthenticationHolderRepository

    @Autowired
    lateinit var configBean: ConfigurationPropertiesBean

    @Autowired
    private lateinit var encrypters: ClientKeyCacheService

    @Autowired
    private lateinit var symmetricCacheService: SymmetricKeyJWTValidatorCacheService

    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    override fun createIdToken(
        client: ClientDetailsEntity,
        request: OAuth2Request,
        issueTime: Date?,
        sub: String?,
        accessToken: OAuth2AccessTokenEntity
    ): JWT? {
        var signingAlg = jwtService.defaultSigningAlgorithm

        if (client.idTokenSignedResponseAlg != null) {
            signingAlg = client.idTokenSignedResponseAlg
        }


        var idToken: JWT? = null

        val idClaims = JWTClaimsSet.Builder()

        // if the auth time claim was explicitly requested OR if the client always wants the auth time, put it in
        if (request.extensions.containsKey(ConnectRequestParameters.MAX_AGE)
            || (request.extensions.containsKey("idtoken")) // TODO: parse the ID Token claims (#473) -- for now assume it could be in there
            || (client.requireAuthTime == true)
        ) {
            when (val authTimestamp = request.extensions[AuthenticationTimeStamper.AUTH_TIMESTAMP]) {
                    // we couldn't find the timestamp!
                null -> logger.warn("Unable to find authentication timestamp! There is likely something wrong with the configuration.")

                is String -> idClaims.claim("auth_time", authTimestamp.toLong() / 1000L)

                else ->
                    logger.warn("Authentication timestamp is of incorrect type (string expected)")
            }
        }

        idClaims.issueTime(issueTime)

        if (client.idTokenValiditySeconds != null) {
            val expiration = Date(System.currentTimeMillis() + (client.idTokenValiditySeconds!! * 1000L))
            idClaims.expirationTime(expiration)
        }

        idClaims.issuer(configBean.issuer)
        idClaims.subject(sub)
        idClaims.audience(Lists.newArrayList(client.clientId))
        idClaims.jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it

        val nonce = request.extensions[ConnectRequestParameters.NONCE] as String?
        if (!Strings.isNullOrEmpty(nonce)) {
            idClaims.claim("nonce", nonce)
        }

        val responseTypes = request.responseTypes

        if (responseTypes.contains("token")) {
            // calculate the token hash
            val at_hash = IdTokenHashUtils.getAccessTokenHash(signingAlg!!, accessToken)
            idClaims.claim("at_hash", at_hash)
        }

        addCustomIdTokenClaims(idClaims, client, request, sub, accessToken)

        if (client.idTokenEncryptedResponseAlg != null && client.idTokenEncryptedResponseAlg != Algorithm.NONE && client.idTokenEncryptedResponseEnc != null && client.idTokenEncryptedResponseEnc != Algorithm.NONE
            && (!Strings.isNullOrEmpty(client.jwksUri) || client.jwks != null)
        ) {
            val encrypter = encrypters.getEncrypter(client)

            if (encrypter != null) {
                idToken =
                    EncryptedJWT(JWEHeader(client.idTokenEncryptedResponseAlg, client.idTokenEncryptedResponseEnc), idClaims.build())

                encrypter.encryptJwt((idToken as JWEObject?)!!)
            } else {
                logger.error("Couldn't find encrypter for client: " + client.clientId)
            }
        } else {
            if (signingAlg == Algorithm.NONE) {
                // unsigned ID token
                idToken = PlainJWT(idClaims.build())
            } else {
                // signed ID token

                if (signingAlg == JWSAlgorithm.HS256 || signingAlg == JWSAlgorithm.HS384 || signingAlg == JWSAlgorithm.HS512) {
                    val header = JWSHeader(
                        signingAlg, null, null, null, null, null, null, null, null, null,
                        jwtService.defaultSignerKeyId,
                        null, null
                    )
                    idToken = SignedJWT(header, idClaims.build())

                    val signer = symmetricCacheService.getSymmetricValidtor(client)

                    // sign it with the client's secret
                    signer!!.signJwt((idToken as SignedJWT?)!!)
                } else {
                    idClaims.claim("kid", jwtService.defaultSignerKeyId)

                    val header = JWSHeader(
                        signingAlg, null, null, null, null, null, null, null, null, null,
                        jwtService.defaultSignerKeyId,
                        null, null
                    )

                    idToken = SignedJWT(header, idClaims.build())

                    // sign it with the server's key
                    jwtService.signJwt((idToken as SignedJWT?)!!)
                }
            }
        }

        return idToken
    }

    /**
     * @throws AuthenticationException
     */
    override fun createRegistrationAccessToken(client: ClientDetailsEntity): OAuth2AccessTokenEntity? {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE))
    }


    override fun createResourceAccessToken(client: ClientDetailsEntity): OAuth2AccessTokenEntity? {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeService.RESOURCE_TOKEN_SCOPE))
    }

    override fun rotateRegistrationAccessTokenForClient(client: ClientDetailsEntity): OAuth2AccessTokenEntity? {
        // revoke any previous tokens
        val oldToken = tokenService.getRegistrationAccessTokenForClient(client)
        if (oldToken != null) {
            val scope = oldToken.scope
            tokenService.revokeAccessToken(oldToken)
            return createAssociatedToken(client, scope)
        } else {
            return null
        }
    }

    private fun createAssociatedToken(client: ClientDetailsEntity, scope: Set<String>?): OAuth2AccessTokenEntity {
        // revoke any previous tokens that might exist, just to be sure

        val oldToken = tokenService.getRegistrationAccessTokenForClient(client)
        if (oldToken != null) {
            tokenService.revokeAccessToken(oldToken)
        }

        // create a new token
        val authorizationParameters: Map<String, String> = Maps.newHashMap()
        val clientAuth = OAuth2Request(
            authorizationParameters, client.clientId,
            Sets.newHashSet(SimpleGrantedAuthority("ROLE_CLIENT")), true,
            scope, null, null, null, null
        )
        val authentication = OAuth2Authentication(clientAuth, null)

        val token = OAuth2AccessTokenEntity()
        token.client = client
        token.scope = scope

        var authHolder = AuthenticationHolderEntity()
        authHolder.authentication = authentication
        authHolder = authenticationHolderRepository.save(authHolder)
        token.authenticationHolder = authHolder

        val claims = JWTClaimsSet.Builder()
            .audience(Lists.newArrayList(client.clientId))
            .issuer(configBean.issuer)
            .issueTime(Date())
            .expirationTime(token.expiration)
            .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it
            .build()

        val signingAlg = jwtService.defaultSigningAlgorithm
        val header = JWSHeader(
            signingAlg, null, null, null, null, null, null, null, null, null,
            jwtService.defaultSignerKeyId,
            null, null
        )
        val signed = SignedJWT(header, claims)

        jwtService.signJwt(signed)

        token.jwt = signed

        return token
    }

    /**
     * Hook for subclasses that allows adding custom claims to the JWT
     * that will be used as id token.
     * @param idClaims the builder holding the current claims
     * @param client information about the requesting client
     * @param request request that caused the id token to be created
     * @param sub subject auf the id token
     * @param accessToken the access token
     */
    protected fun addCustomIdTokenClaims(
        idClaims: JWTClaimsSet.Builder?, client: ClientDetailsEntity?, request: OAuth2Request?,
        sub: String?, accessToken: OAuth2AccessTokenEntity?
    ) {
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DefaultOIDCTokenService::class.java)
    }
}