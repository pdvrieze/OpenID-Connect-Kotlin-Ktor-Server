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
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension


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
        Mockito.reset(mockDynamicService, mockStaticService)
    }


    @Test
    fun getServerConfiguration_useStatic(): Unit {
        Mockito.`when`(mockStaticService.getServerConfiguration(issuer)).thenReturn(mockServerConfig)

        val result = hybridService.getServerConfiguration(issuer)

        Mockito.verify(mockStaticService).getServerConfiguration(issuer)
        Mockito.verify(mockDynamicService, Mockito.never()).getServerConfiguration(ArgumentMatchers.anyString())
        assertEquals(mockServerConfig, result)
    }

    @Test
    fun getServerConfiguration_useDynamic(): Unit {
        Mockito.`when`(mockStaticService.getServerConfiguration(issuer)).thenReturn(null)
        Mockito.`when`(mockDynamicService.getServerConfiguration(issuer)).thenReturn(mockServerConfig)

        val result = hybridService.getServerConfiguration(issuer)

        Mockito.verify(mockStaticService).getServerConfiguration(issuer)
        Mockito.verify(mockDynamicService).getServerConfiguration(issuer)
        assertEquals(mockServerConfig, result)
    }

    @Test
    fun getServerConfiguration_noIssuer(): Unit {
        // unused by mockito (causs unnecessary stubbing exception
//		Mockito.when(mockStaticService.getServerConfiguration(issuer)).thenReturn(mockServerConfig);
//		Mockito.when(mockDynamicService.getServerConfiguration(issuer)).thenReturn(mockServerConfig);

        val badIssuer = "www.badexample.com"

        val result = hybridService.getServerConfiguration(badIssuer)

        Mockito.verify(mockStaticService).getServerConfiguration(badIssuer)
        Mockito.verify(mockDynamicService).getServerConfiguration(badIssuer)
        assertThat(result, CoreMatchers.`is`(CoreMatchers.nullValue()))
    }
}
