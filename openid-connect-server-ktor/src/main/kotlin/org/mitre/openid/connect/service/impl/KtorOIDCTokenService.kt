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
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.KtorAuthenticationHolder
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.util.IdTokenHashUtils
import org.mitre.util.getLogger
import java.time.Instant
import java.util.*

/**
 * Default implementation of service to create specialty OpenID Connect tokens.
 *
 * @author Amanda Anganes
 */
class KtorOIDCTokenService(
    val jwtService: JWTSigningAndValidationService,
    val authenticationHolderRepository: AuthenticationHolderRepository,
    val configBean: ConfigurationPropertiesBean,
    val encrypters: ClientKeyCacheService,
    val symmetricCacheService: SymmetricKeyJWTValidatorCacheService,
    val tokenService: OAuth2TokenEntityService,
) : OIDCTokenService {

    override suspend fun createIdToken(
        client: OAuthClientDetails,
        request: AuthorizationRequest,
        issueTime: Date?,
        sub: String?,
        accessToken: OAuth2AccessToken.Builder
    ): JWT? {
        var signingAlg = jwtService.defaultSigningAlgorithm

        client.idTokenSignedResponseAlg?.let { signingAlg = it }

        var idToken: JWT? = null

        val idClaims = JWTClaimsSet.Builder()

        // if the auth time claim was explicitly requested OR if the client always wants the auth time, put it in
        if ((request is OpenIdAuthorizationRequest && (request.maxAge != null || request.idToken != null)) // TODO: parse the ID Token claims (#473) -- for now assume it could be in there
            || (client.requireAuthTime == true)
        ) {
            when (val approval = request.approval) {
                    // we couldn't find the timestamp!
                null -> logger.warn("Unable to find authentication timestamp! There is likely something wrong with the configuration.")

                else -> idClaims.claim("auth_time", approval.approvalTime.epochSecond)
            }
        }

        idClaims.issueTime(issueTime)

        if (client.idTokenValiditySeconds != null) {
            val expiration = Date(System.currentTimeMillis() + (client.idTokenValiditySeconds!! * 1000L))
            idClaims.expirationTime(expiration)
        }

        idClaims.issuer(configBean.issuer)
        idClaims.subject(sub)
        idClaims.audience(listOf(client.clientId))
        idClaims.jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it

        val nonce = (request as? OpenIdAuthorizationRequest)?.nonce
        if (!nonce.isNullOrEmpty()) {
            idClaims.claim("nonce", nonce)
        }

        val responseTypes = request.responseTypes

        if (responseTypes!=null && responseTypes.contains("token")) {
            // calculate the token hash
            val at_hash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken)
            idClaims.claim("at_hash", at_hash)
        }

        addCustomIdTokenClaims(idClaims, client, request, sub, accessToken)

        if (client.idTokenEncryptedResponseAlg != null && client.idTokenEncryptedResponseAlg != Algorithm.NONE && client.idTokenEncryptedResponseEnc != null && client.idTokenEncryptedResponseEnc != Algorithm.NONE
            && (!client.jwksUri.isNullOrEmpty() || client.jwks != null)
        ) {
            val encrypter = encrypters.getEncrypter(client)

            if (encrypter != null) {
                idToken =
                    EncryptedJWT(JWEHeader(client.idTokenEncryptedResponseAlg, client.idTokenEncryptedResponseEnc), idClaims.build())

                encrypter.encryptJwt((idToken as JWEObject?)!!)
            } else {
                logger.error("Couldn't find encrypter for client: ${client.clientId}")
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

                    val signer = symmetricCacheService.getSymmetricValidator(client)

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
    override fun createRegistrationAccessToken(client: OAuthClientDetails): OAuth2AccessTokenEntity {
        return createAssociatedToken(client, hashSetOf(SystemScopeService.REGISTRATION_TOKEN_SCOPE))
    }


    override fun createResourceAccessToken(client: OAuthClientDetails): OAuth2AccessTokenEntity {
        return createAssociatedToken(client, hashSetOf(SystemScopeService.RESOURCE_TOKEN_SCOPE))
    }

    override fun rotateRegistrationAccessTokenForClient(client: OAuthClientDetails): OAuth2AccessTokenEntity? {
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

    private fun createAssociatedToken(client: OAuthClientDetails, scope: Set<String>?): OAuth2AccessTokenEntity {
        // revoke any previous tokens that might exist, just to be sure

        val oldToken = tokenService.getRegistrationAccessTokenForClient(client)
        if (oldToken != null) {
            tokenService.revokeAccessToken(oldToken)
        }

        // create a new token
        val now = Instant.now()
        val clientAuth =
            PlainAuthorizationRequest.Builder(clientId = client.clientId).also { b ->
                @OptIn(InternalForStorage::class)
                b.requestParameters = emptyMap()
                b.requestTime = now
                b.authorities = hashSetOf(LocalGrantedAuthority("ROLE_CLIENT"))
                b.approval = AuthorizationRequest.Approval(now)
                b.scope = scope ?: emptySet()
                b.requestTime = now
            }.build()
        val authentication = AuthenticatedAuthorizationRequest(clientAuth, null)

        val tokenBuilder = OAuth2AccessTokenEntity.Builder()
        tokenBuilder.setClient(client)
        tokenBuilder.scope = scope ?: emptySet()

        val authHolder = authenticationHolderRepository.save(KtorAuthenticationHolder(authentication))
        tokenBuilder.setAuthenticationHolder(authHolder)

        val claims = JWTClaimsSet.Builder()
            .audience(listOf(client.clientId))
            .issuer(configBean.issuer)
            .issueTime(Date())
            .expirationTime(tokenBuilder.expiration)
            .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it
            .build()

        val signingAlg = jwtService.defaultSigningAlgorithm
        val header = JWSHeader(
            signingAlg, null, null, null, null, null, null, null, null, null,
            jwtService.defaultSignerKeyId, true,
            null, null
        )
        val signed = SignedJWT(header, claims)

        jwtService.signJwt(signed)

        tokenBuilder.jwt = signed

        return tokenBuilder.build(ClientDetailsEntity.from(client), authenticationHolderRepository, tokenService)
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
        idClaims: JWTClaimsSet.Builder, client: OAuthClientDetails, request: AuthorizationRequest?,
        sub: String?, accessToken: OAuth2AccessToken.Builder?
    ) {
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorOIDCTokenService>()
    }
}
