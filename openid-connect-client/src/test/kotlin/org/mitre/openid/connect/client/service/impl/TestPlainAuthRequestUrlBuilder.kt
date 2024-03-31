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

import com.google.common.collect.ImmutableMap
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.AuthenticationServiceException

/**
 * @author wkim
 */
class TestPlainAuthRequestUrlBuilder {
    // Test fixture:
    lateinit var serverConfig: ServerConfiguration
    lateinit var clientConfig: RegisteredClient

    private val urlBuilder = PlainAuthRequestUrlBuilder()

    @BeforeEach
    fun prepare() {
        serverConfig = mock<ServerConfiguration>()
        whenever(serverConfig.authorizationEndpointUri).thenReturn("https://server.example.com/authorize")

        clientConfig = mock<RegisteredClient>()
        whenever(clientConfig.clientId).thenReturn("s6BhdRkqt3")
        whenever(clientConfig.scope).thenReturn(hashSetOf("openid", "profile"))
    }

    @Test
    fun buildAuthRequestUrl() {
        val expectedUrl = "https://server.example.com/authorize?" +
                "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&scope=openid+profile" +  // plus sign used for space per application/x-www-form-encoded standard
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2F" +
                "&nonce=34fasf3ds" +
                "&state=af0ifjsldkj" +
                "&foo=bar"

        val options: Map<String, String> = ImmutableMap.of("foo", "bar")

        val actualUrl =
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, "https://client.example.org/", "34fasf3ds", "af0ifjsldkj", options, null)

        assertEquals(expectedUrl, actualUrl)
    }

    @Test
    fun buildAuthRequestUrl_withLoginHint() {
        val expectedUrl = "https://server.example.com/authorize?" +
                "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&scope=openid+profile" +  // plus sign used for space per application/x-www-form-encoded standard
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2F" +
                "&nonce=34fasf3ds" +
                "&state=af0ifjsldkj" +
                "&foo=bar" +
                "&login_hint=bob"

        val options: Map<String, String> = ImmutableMap.of("foo", "bar")

        val actualUrl =
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, "https://client.example.org/", "34fasf3ds", "af0ifjsldkj", options, "bob")

        assertEquals(expectedUrl, actualUrl)
    }

    @Test
    fun buildAuthRequestUrl_badUri() {
        whenever(serverConfig.authorizationEndpointUri).thenReturn("e=mc^2")

        val options: Map<String, String> = ImmutableMap.of("foo", "bar")

        assertThrows<AuthenticationServiceException> {
            urlBuilder.buildAuthRequestUrl(serverConfig, clientConfig, "example.com", "", "", options, null)
        }
    }
}
