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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.never
import org.mockito.kotlin.reset
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever


/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
class TestHybridServerConfigurationService {
    @Mock
    private lateinit var mockStaticService: StaticServerConfigurationService

    @Mock
    private lateinit var mockDynamicService: DynamicServerConfigurationService

    @InjectMocks
    private lateinit var hybridService: HybridServerConfigurationService

    @Mock
    private lateinit var mockServerConfig: ServerConfiguration

    private val issuer = "https://www.example.com/"

    @BeforeEach
    fun prepare() {
        reset(mockDynamicService, mockStaticService)
    }


    @Test
    fun getServerConfiguration_useStatic() = runBlocking {
        whenever(mockStaticService.getServerConfiguration(issuer)).thenReturn(mockServerConfig)

        val result = hybridService.getServerConfiguration(issuer)

        verify(mockStaticService).getServerConfiguration(issuer)
        verify(mockDynamicService, never()).getServerConfiguration(ArgumentMatchers.anyString())
        assertEquals(mockServerConfig, result)
    }

    @Test
    fun getServerConfiguration_useDynamic(): Unit = runBlocking {
        whenever(mockStaticService.getServerConfiguration(issuer)).thenReturn(null)
        whenever(mockDynamicService.getServerConfiguration(issuer)).thenReturn(mockServerConfig)

        val result = hybridService.getServerConfiguration(issuer)

        verify(mockStaticService).getServerConfiguration(issuer)
        verify(mockDynamicService).getServerConfiguration(issuer)
        assertEquals(mockServerConfig, result)
    }

    @Test
    fun getServerConfiguration_noIssuer(): Unit = runBlocking {
        // unused by mockito (causs unnecessary stubbing exception
//		whenever(mockStaticService.getServerConfiguration(issuer)).thenReturn(mockServerConfig);
//		whenever(mockDynamicService.getServerConfiguration(issuer)).thenReturn(mockServerConfig);

        val badIssuer = "www.badexample.com"

        val result = hybridService.getServerConfiguration(badIssuer)

        verify(mockStaticService).getServerConfiguration(badIssuer)
        verify(mockDynamicService).getServerConfiguration(badIssuer)
        assertNull(result)
    }
}
