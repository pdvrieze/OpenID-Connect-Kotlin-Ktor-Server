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
package org.mitre.openid.connect.service.impl.spring

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever
import java.text.ParseException
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
class TestSpringOIDCTokenService {
    private val configBean = ConfigurationPropertiesBean(javaClass.name, "topbar")
    private val client = ClientDetailsEntity.Builder(clientId = CLIENT_ID).build()
    private val request: AuthorizationRequest = AuthorizationRequest(clientId = CLIENT_ID, requestTime = Instant.now())
    private val accessToken = OAuth2AccessTokenEntity(
        authenticationHolder = AuthenticationHolderEntity(requestTime = request.requestTime),
        expirationInstant = Instant.now().plusSeconds(120),
        jwt = PlainJWT(JWTClaimsSet.Builder().build()),
    )

    @Mock
    private lateinit var jwtService: JWTSigningAndValidationService

    @BeforeEach
    fun prepare() {
        configBean.issuer = "https://auth.example.org/"

        whenever(jwtService.defaultSigningAlgorithm).thenReturn(JWSAlgorithm.RS256)
        whenever(jwtService.defaultSignerKeyId).thenReturn(KEY_ID)
    }

    @Test
    @Throws(ParseException::class)
    fun invokesCustomClaimsHook() {
        val s: DefaultOIDCTokenService = object : DefaultOIDCTokenService() {
            override fun addCustomIdTokenClaims(
                idClaims: JWTClaimsSet.Builder,
                client: OAuthClientDetails,
                request: AuthorizationRequest?,
                sub: String?,
                accessToken: OAuth2AccessToken.Builder?
            ) {
                idClaims.claim("test", "foo")
            }
        }
        configure(s)

        val token = runBlocking { s.createIdToken(client, request, Date(), "sub", accessToken.builder())!! }
        assertEquals("foo", token.jwtClaimsSet.getClaim("test"))
    }


    private fun configure(s: DefaultOIDCTokenService) {
        s.configBean = configBean
        s.jwtService = jwtService
    }

    companion object {
        private const val CLIENT_ID = "client"
        private const val KEY_ID = "key"
    }
}
