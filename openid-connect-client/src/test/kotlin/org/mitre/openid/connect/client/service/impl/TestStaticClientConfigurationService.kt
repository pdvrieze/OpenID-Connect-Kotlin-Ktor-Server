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

import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
class TestStaticClientConfigurationService {
    private lateinit var service: StaticClientConfigurationService

    private val issuer = "https://www.example.com/"

    @Mock
    private lateinit var mockClient: RegisteredClient

    @Mock
    private lateinit var mockServerConfig: ServerConfiguration

    @BeforeEach
    fun prepare() {
        service = StaticClientConfigurationService()

        val clients: MutableMap<String?, RegisteredClient> = HashMap()
        clients[issuer] = mockClient

        service.clients = clients

        whenever(mockServerConfig.issuer).thenReturn(issuer)
    }

    @Test
    fun getClientConfiguration_success() {
        val result = service.getClientConfiguration(mockServerConfig)

        assertThat(mockClient, CoreMatchers.`is`(CoreMatchers.notNullValue()))
        assertEquals(mockClient, result)
    }

    @Test
    fun getClientConfiguration_noIssuer() {
        whenever(mockServerConfig.issuer).thenReturn("www.badexample.net")

        val actualClient = service.getClientConfiguration(mockServerConfig)

        assertThat(actualClient, CoreMatchers.`is`(CoreMatchers.nullValue()))
    }
}
