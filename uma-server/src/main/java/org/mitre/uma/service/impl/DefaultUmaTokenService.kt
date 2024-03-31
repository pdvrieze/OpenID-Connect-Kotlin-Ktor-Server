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
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Service
import java.util.*

/**
 * @author jricher
 */
@Service("defaultUmaTokenService")
class DefaultUmaTokenService : UmaTokenService {
    @Autowired
    private lateinit var authenticationHolderRepository: AuthenticationHolderRepository

    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var jwtService: JWTSigningAndValidationService


    override fun createRequestingPartyToken(
        o2auth: OAuth2Authentication,
        ticket: PermissionTicket,
        policy: Policy
    ): OAuth2AccessTokenEntity? {
        val token = OAuth2AccessTokenEntity()
        val authHolder = AuthenticationHolderEntity().run {
            authentication = o2auth
            authenticationHolderRepository.save(this)
        }

        token.authenticationHolder = authHolder

        val client = clientService.loadClientByClientId(o2auth.oAuth2Request.clientId)
        token.client = client

        val ticketScopes = ticket.permission!!.scopes!!
        val policyScopes = policy.scopes!!

        val perm = Permission()
        perm.resourceSet = ticket.permission!!.resourceSet
        perm.scopes = ticketScopes.intersect(policyScopes)

        token.permissions = hashSetOf(perm)

        val claims = JWTClaimsSet.Builder()

        claims.audience(listOf(ticket.permission!!.resourceSet!!.id.toString()))
        claims.issuer(config.issuer)
        claims.jwtID(UUID.randomUUID().toString())

        if (config.rqpTokenLifeTime != null) {
            val exp = Date(System.currentTimeMillis() + config.rqpTokenLifeTime!! * 1000L)

            claims.expirationTime(exp)
            token.expiration = exp
        }


        val signingAlgorithm = jwtService.defaultSigningAlgorithm
        val header = JWSHeader(
            signingAlgorithm, null, null, null, null, null, null, null, null, null,
            jwtService.defaultSignerKeyId,
            null, null
        )
        val signed = SignedJWT(header, claims.build())

        jwtService.signJwt(signed)

        token.jwt = signed

        tokenService.saveAccessToken(token)

        return token
    }
}
