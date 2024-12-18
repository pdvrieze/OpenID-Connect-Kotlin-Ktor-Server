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

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
class TestStaticServerConfigurationService {
    private lateinit var service: StaticServerConfigurationService

    private val issuer = "https://www.example.com/"

    @Mock
    private lateinit var mockServerConfig: ServerConfiguration

    @BeforeEach
    fun prepare() {

        val servers: MutableMap<String, ServerConfiguration> = HashMap()
        servers[issuer] = mockServerConfig

        service = StaticServerConfigurationService(servers)
    }

    @Test
    fun getServerConfiguration_success(): Unit = runBlocking {
        val result = service.getServerConfiguration(issuer)

        assertNotNull(mockServerConfig)
        assertEquals(mockServerConfig, result)
    }

    @Test
    fun getClientConfiguration_noIssuer(): Unit = runBlocking {
        val result = service.getServerConfiguration("www.badexample.net")
        assertNull(result)
    }
}
