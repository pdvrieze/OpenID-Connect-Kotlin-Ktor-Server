/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.service.impl

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.Policy
import org.mitre.uma.service.UmaTokenService
import java.util.*

/**
 * @author jricher
 */
class DefaultUmaTokenService(
    private val authenticationHolderRepository: AuthenticationHolderRepository,
    private val tokenService: OAuth2TokenEntityService,
    private val clientService: ClientDetailsEntityService,
    private val config: ConfigurationPropertiesBean,
    private val jwtService: JWTSigningAndValidationService,
) : UmaTokenService {

    override fun createRequestingPartyToken(
        authorizationRequest: AuthenticatedAuthorizationRequest,
        ticket: PermissionTicket,
        policy: Policy
    ): OAuth2AccessTokenEntity {
        val tokenBuilder = OAuth2AccessTokenEntity.Builder()
        val authHolder = authenticationHolderRepository.save(AuthenticationHolderEntity(authorizationRequest))

        tokenBuilder.setAuthenticationHolder(authHolder)

        val client = clientService.loadClientByClientId(authorizationRequest.authorizationRequest.clientId)!!
        tokenBuilder.setClient(client)

        val ticketScopes = ticket.permission.scopes
        val policyScopes = policy.scopes

        val perm = Permission(
            resourceSet = ticket.permission.resourceSet,
            scopes = ticketScopes.intersect(policyScopes),
        )

        tokenBuilder.permissions = hashSetOf(perm)

        val claims = JWTClaimsSet.Builder().apply {
            audience(listOf(ticket.permission.resourceSet.id.toString()))
            issuer(config.issuer)
            jwtID(UUID.randomUUID().toString())
        }


        if (config.rqpTokenLifeTime != null) {
            val exp = Date(System.currentTimeMillis() + config.rqpTokenLifeTime!! * 1000L)

            claims.expirationTime(exp)
            tokenBuilder.expiration = exp
        }


        val signingAlgorithm = jwtService.defaultSigningAlgorithm
        val header = JWSHeader.Builder(signingAlgorithm)
            .keyID(jwtService.defaultSignerKeyId)
            .build()

        val signed = SignedJWT(header, claims.build())

        jwtService.signJwt(signed)

        tokenBuilder.jwt = signed

        val token = tokenBuilder.build(clientService, authenticationHolderRepository, tokenService)

        tokenService.saveAccessToken(token)

        return token
    }
}
