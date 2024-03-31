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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.UserInfoService
import org.mockito.ArgumentMatchers.anyString
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import java.text.ParseException

@ExtendWith(MockitoExtension::class)
class TestConnectTokenEnhancer {
    private val configBean = ConfigurationPropertiesBean()

    @Mock
    private lateinit var jwtService: JWTSigningAndValidationService

    @Mock
    private lateinit var clientService: ClientDetailsEntityService

    @Mock
    private lateinit var userInfoService: UserInfoService

    @Mock
    private lateinit var connectTokenService: OIDCTokenService

    @Mock
    private lateinit var authentication: OAuth2Authentication

    private val request: OAuth2Request = object : OAuth2Request(CLIENT_ID) {}

    @InjectMocks
    private var enhancer = ConnectTokenEnhancer()

    @BeforeEach
    fun prepare() {
        configBean.issuer = "https://auth.example.org/"
        enhancer.configBean = configBean

        val client = ClientDetailsEntity()
        client.clientId = CLIENT_ID
        whenever(clientService.loadClientByClientId(anyString())).thenReturn(client)
        whenever(authentication.oAuth2Request).thenReturn(request)
        whenever(jwtService.defaultSigningAlgorithm).thenReturn(JWSAlgorithm.RS256)
        whenever(jwtService.defaultSignerKeyId).thenReturn(KEY_ID)
    }

    @Test
    @Throws(ParseException::class)
    fun invokesCustomClaimsHook() {
        configure(object : ConnectTokenEnhancer() {
            override fun addCustomAccessTokenClaims(
                builder: JWTClaimsSet.Builder, token: OAuth2AccessTokenEntity?,
                authentication: OAuth2Authentication?
            ) {
                builder.claim("test", "foo")
            }
        }.also { enhancer = it })

        val token = OAuth2AccessTokenEntity()

        val enhanced = enhancer.enhance(token, authentication) as OAuth2AccessTokenEntity
        assertEquals("foo", enhanced.jwt!!.jwtClaimsSet.getClaim("test"))
    }

    private fun configure(e: ConnectTokenEnhancer) {
        e.configBean = configBean
        e.jwtService = jwtService
        e.clientService = clientService
    }

    companion object {
        private const val CLIENT_ID = "client"
        private const val KEY_ID = "key"
    }
}
