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
package org.mitre.openid.connect.service.impl

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.whenever
import org.springframework.security.oauth2.provider.OAuth2Request
import java.text.ParseException
import java.util.*

@RunWith(MockitoJUnitRunner::class)
class TestDefaultOIDCTokenService {
    private val configBean = ConfigurationPropertiesBean()
    private val client = ClientDetailsEntity()
    private val accessToken = OAuth2AccessTokenEntity()
    private val request: OAuth2Request = object : OAuth2Request(CLIENT_ID) {}

    @Mock
    private lateinit var jwtService: JWTSigningAndValidationService

    @Before
    fun prepare() {
        configBean.issuer = "https://auth.example.org/"

        client.clientId = CLIENT_ID
        whenever(jwtService.defaultSigningAlgorithm).thenReturn(JWSAlgorithm.RS256)
        whenever(jwtService.defaultSignerKeyId).thenReturn(KEY_ID)
    }

    @Test
    @Throws(ParseException::class)
    fun invokesCustomClaimsHook() {
        val s: DefaultOIDCTokenService = object : DefaultOIDCTokenService() {
            override fun addCustomIdTokenClaims(
                idClaims: JWTClaimsSet.Builder, client: ClientDetailsEntity?, request: OAuth2Request?,
                sub: String?, accessToken: OAuth2AccessTokenEntity?
            ) {
                idClaims.claim("test", "foo")
            }
        }
        configure(s)

        val token = s.createIdToken(client, request, Date(), "sub", accessToken)
        assertEquals("foo", token!!.jwtClaimsSet.getClaim("test"))
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
