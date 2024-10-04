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
package org.mitre.openid.connect.client.service.impl

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.fail
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.web.util.UriComponentsBuilder
import java.net.URISyntaxException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.text.ParseException

/**
 * @author wkim
 */
class TestSignedAuthRequestUrlBuilder {
    // Test fixture:
    private lateinit var serverConfig: ServerConfiguration
    private lateinit var clientConfig: RegisteredClient

    private val redirectUri = "https://client.example.org/"
    private val nonce = "34fasf3ds"
    private val state = "af0ifjsldkj"
    private val responseType = "code"
    private val options: Map<String, String> = mapOf("foo" to "bar")


    // RSA key properties:
    // {@link package com.nimbusds.jose.jwk#RSAKey}
    private val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zw" +
            "u1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc" +
            "5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8K" +
            "JZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh" +
            "6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    private val e = "AQAB"
    private val d = "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknc" +
            "hnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5" +
            "N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSa" +
            "wm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk1" +
            "9Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
    private val alg = "RS256"
    private val kid = "2011-04-29"
    private val loginHint = "bob"

    private lateinit var signingAndValidationService: DefaultJWTSigningAndValidationService

    private val urlBuilder = SignedAuthRequestUrlBuilder()

    @BeforeEach
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun prepare() {
        val key =
            RSAKey(Base64URL(n), Base64URL(e), Base64URL(d), KeyUse.SIGNATURE, null, Algorithm(alg), kid, null, null, null, null, null)
        val keys: MutableMap<String, JWK> = mutableMapOf("client" to key)

        signingAndValidationService = DefaultJWTSigningAndValidationService(keys)
        signingAndValidationService.defaultSignerKeyId = "client"
        signingAndValidationService.defaultSigningAlgorithmName = alg

        urlBuilder.signingAndValidationService = signingAndValidationService

        serverConfig = mock<ServerConfiguration>()
        whenever(serverConfig.authorizationEndpointUri).thenReturn("https://server.example.com/authorize")

        clientConfig = mock<RegisteredClient>()
        whenever(clientConfig.clientId).thenReturn("s6BhdRkqt3")
        whenever(clientConfig.scope).thenReturn(hashSetOf("openid", "profile"))
    }

    /**
     * This test takes the URI from the result of building a signed request
     * and checks that the JWS object parsed from the request URI matches up
     * with the expected claim values.
     */
    @Test
    fun buildAuthRequestUrl(): Unit = runBlocking {
        val requestUri =
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, redirectUri, nonce, state, options, null)

        // parsing the result
        val builder: UriComponentsBuilder = try {
            UriComponentsBuilder.fromUri(requestUri.toURI())
        } catch (e1: URISyntaxException) {
            fail("URISyntaxException was thrown.")
        }

        val components = builder.build()
        val jwtString = components.queryParams["request"]!![0]

        val claims: JWTClaimsSet? = try {
            val jwt = SignedJWT.parse(jwtString)
            jwt.jwtClaimsSet
        } catch (e: ParseException) {
            fail("ParseException was thrown.")
        }

        assertEquals(responseType, claims!!.getClaim("response_type"))
        assertEquals(clientConfig.clientId, claims.getClaim("client_id"))

        val scopeList = (claims.getStringClaim("scope") as String)
                .split(" ".toRegex())
                .dropLastWhile { it.isEmpty() }
                .toList()

        assertTrue(scopeList.containsAll(clientConfig.scope ?: emptySet()))

        assertEquals(redirectUri, claims.getClaim("redirect_uri"))
        assertEquals(nonce, claims.getClaim("nonce"))
        assertEquals(state, claims.getClaim("state"))
        for (claim in options.keys) {
            assertEquals(options[claim], claims.getClaim(claim))
        }
    }

    @Test
    fun buildAuthRequestUrl_withLoginHint(): Unit = runBlocking {
        val requestUri =
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, redirectUri, nonce, state, options, loginHint)

        // parsing the result
        val builder: UriComponentsBuilder= try {
            UriComponentsBuilder.fromUri(requestUri.toURI())
        } catch (e1: URISyntaxException) {
            fail("URISyntaxException was thrown.")
        }

        val components = builder.build()
        val jwtString = components.queryParams["request"]!![0]

        val claims: JWTClaimsSet = try {
            SignedJWT.parse(jwtString).jwtClaimsSet
        } catch (e: ParseException) {
            fail("ParseException was thrown.")
        }

        assertEquals(responseType, claims.getClaim("response_type"))
        assertEquals(clientConfig.clientId, claims.getClaim("client_id"))

        val scopeList =
            (claims.getClaim("scope") as String).split(" ".toRegex()).dropLastWhile { it.isEmpty() }
                .toList()
        assertTrue(scopeList.containsAll(clientConfig.scope ?: emptySet()))

        assertEquals(redirectUri, claims.getClaim("redirect_uri"))
        assertEquals(nonce, claims.getClaim("nonce"))
        assertEquals(state, claims.getClaim("state"))
        for (claim in options.keys) {
            assertEquals(options[claim], claims.getClaim(claim))
        }
        assertEquals(loginHint, claims.getClaim("login_hint"))
    }

    @Test
    fun buildAuthRequestUrl_badUri(): Unit = runBlocking {
        whenever(serverConfig.authorizationEndpointUri).thenReturn("e=mc^2")

        assertThrows<URISyntaxException> {
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, "example.com", "", "", options, null)
        }
    }
}
