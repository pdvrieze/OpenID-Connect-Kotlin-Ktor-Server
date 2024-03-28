package org.mitre.openid.connect.client.service.impl

import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.MockitoJUnitRunner

/**
 * @author wkim
 */
@RunWith(MockitoJUnitRunner::class)
class TestHybridClientConfigurationService {
    @Mock
    private lateinit var mockStaticService: StaticClientConfigurationService

    @Mock
    private lateinit var mockDynamicService: DynamicRegistrationClientConfigurationService

    @InjectMocks
    private lateinit var hybridService: HybridClientConfigurationService

    // test fixture
    @Mock
    private lateinit var mockClient: RegisteredClient

    @Mock
    private lateinit var mockServerConfig: ServerConfiguration

    private val issuer = "https://www.example.com/"

    @Before
    fun prepare() {
        Mockito.reset(mockDynamicService, mockStaticService)

        // unused by mockito (causs unnecessary stubbing exception
//		Mockito.when(mockServerConfig.getIssuer()).thenReturn(issuer);
    }

    @Test
    fun getClientConfiguration_useStatic() {
        Mockito.`when`(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient)

        val result = hybridService.getClientConfiguration(mockServerConfig)

        Mockito.verify(mockStaticService).getClientConfiguration(mockServerConfig)
        Mockito.verify(mockDynamicService, Mockito.never())
            .getClientConfiguration(ArgumentMatchers.any() ?: mockServerConfig)
        Assert.assertEquals(mockClient, result)
    }

    @Test
    fun getClientConfiguration_useDynamic() {
        Mockito.`when`(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(null)
        Mockito.`when`(mockDynamicService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient)

        val result = hybridService.getClientConfiguration(mockServerConfig)

        Mockito.verify(mockStaticService).getClientConfiguration(mockServerConfig)
        Mockito.verify(mockDynamicService).getClientConfiguration(mockServerConfig)
        Assert.assertEquals(mockClient, result)
    }

    @Test
    fun getClientConfiguration_noIssuer() {
        // The mockServerConfig is known to both services
        // unused by mockito (causs unnecessary stubbing exception
//		Mockito.when(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient);
//		Mockito.when(mockDynamicService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient);

        // But oh noes! We're going to ask it to find us some other issuer
        // unused by mockito (causs unnecessary stubbing exception

        val badIssuer = Mockito.mock(ServerConfiguration::class.java)

        //		Mockito.when(badIssuer.getIssuer()).thenReturn("www.badexample.com");
        val result = hybridService.getClientConfiguration(badIssuer)

        Mockito.verify(mockStaticService).getClientConfiguration(badIssuer)
        Mockito.verify(mockDynamicService).getClientConfiguration(badIssuer)
        MatcherAssert.assertThat(result, CoreMatchers.`is`(CoreMatchers.nullValue()))
    }
}
