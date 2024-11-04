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
package org.mitre.openid.connect.util

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.openid.connect.util.IdTokenHashUtils.getAccessTokenHash
import org.mitre.openid.connect.util.IdTokenHashUtils.getCodeHash
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness


/**
 *
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestIdTokenHashUtils {
    @Mock
    lateinit var mockToken256: OAuth2AccessTokenEntity

    @Mock
    lateinit var mockToken384: OAuth2AccessTokenEntity

    @Mock
    lateinit var mockToken512: OAuth2AccessTokenEntity

    @Test
    fun getAccessTokenHash256(): Unit {
        /*
         * Claims for first token:
         * claims.setType("JWT");
         * claims.setIssuer("www.example.com");
         * claims.setSubject("example_user");
         * claims.setClaim("alg", "HS256");
         */

        whenever(mockToken256.jwt)
            .thenReturn(JWTParser.parse("eyJhbGciOiJub25lIn0.eyJhbGciOiJIUzI1NiIsInN1YiI6ImV4YW1wbGVfdXNlciIsImlzcyI6Ind3dy5leGFtcGxlLmNvbSIsInR5cCI6IkpXVCJ9."))

        mockToken256.jwt.serialize()
        val expectedHash = Base64URL("EP1gXNeESRH-n57baopfTQ")

        val resultHash = getAccessTokenHash(JWSAlgorithm.HS256, mockToken256)

        assertEquals(expectedHash, resultHash)
    }

    @Test
    fun getAccessTokenHash384(): Unit {
        /*
		 * Claims for second token
		 * claims = new JWTClaimsSet();
		 * claims.setType("JWT");
		 * claims.setIssuer("www.another-example.net");
		 * claims.setSubject("another_user");
		 * claims.setClaim("alg", "ES384");
		 */
        whenever(mockToken384.jwt)
            .thenReturn(JWTParser.parse("eyJhbGciOiJub25lIn0.eyJhbGciOiJFUzM4NCIsInN1YiI6ImFub3RoZXJfdXNlciIsImlzcyI6Ind3dy5hbm90aGVyLWV4YW1wbGUubmV0IiwidHlwIjoiSldUIn0."))

        /*
         * independently generate hash
         * ascii of token = eyJhbGciOiJub25lIn0.eyJhbGciOiJFUzM4NCIsInN1YiI6ImFub3RoZXJfdXNlciIsImlzcyI6Ind3dy5hbm90aGVyLWV4YW1wbGUubmV0IiwidHlwIjoiSldUIn0.
         * base64url of hash = BWfFK73PQI36M1rg9R6VjMyWOE0-XvBK
         */

        mockToken384.jwt.serialize()
        val expectedHash = Base64URL("BWfFK73PQI36M1rg9R6VjMyWOE0-XvBK")

        val resultHash = getAccessTokenHash(JWSAlgorithm.ES384, mockToken384)

        assertEquals(expectedHash, resultHash)
    }

    @Test
    fun getAccessTokenHash512() {
        /*
		 * Claims for third token:
		 * claims = new JWTClaimsSet();
		 * claims.setType("JWT");
		 * claims.setIssuer("www.different.com");
		 * claims.setSubject("different_user");
		 * claims.setClaim("alg", "RS512");
		 */
        whenever(mockToken512.jwt)
            .thenReturn(JWTParser.parse("eyJhbGciOiJub25lIn0.eyJhbGciOiJSUzUxMiIsInN1YiI6ImRpZmZlcmVudF91c2VyIiwiaXNzIjoid3d3LmRpZmZlcmVudC5jb20iLCJ0eXAiOiJKV1QifQ."))

        /*
         * independently generate hash
         * ascii of token = eyJhbGciOiJub25lIn0.eyJhbGciOiJSUzUxMiIsInN1YiI6ImRpZmZlcmVudF91c2VyIiwiaXNzIjoid3d3LmRpZmZlcmVudC5jb20iLCJ0eXAiOiJKV1QifQ.
         * base64url of hash = vGH3QMY-knpACkLgzdkTqu3C9jtvbf2Wk_RSu2vAx8k
         */

        mockToken512.jwt.serialize()
        val expectedHash = Base64URL("vGH3QMY-knpACkLgzdkTqu3C9jtvbf2Wk_RSu2vAx8k")

        val resultHash = getAccessTokenHash(JWSAlgorithm.RS512, mockToken512)

        assertEquals(expectedHash, resultHash)
    }

    @Test
    fun getCodeHash512() {
        val testCode = "b0x0rZ"

        val expectedHash = Base64URL("R5DCRi5eOjlvyTAJfry2dNM9adJ2ElpDEKYYByYU920") // independently generated

        val resultHash = getCodeHash(JWSAlgorithm.ES512, testCode)

        assertEquals(expectedHash, resultHash)
    }
}
