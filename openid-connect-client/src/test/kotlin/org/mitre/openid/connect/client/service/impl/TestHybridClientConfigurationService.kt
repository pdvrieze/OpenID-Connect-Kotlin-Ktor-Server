package org.mitre.openid.connect.client.service.impl

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.reset
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
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

    @BeforeEach
    fun prepare() {
        reset(mockDynamicService, mockStaticService)


        // unused by mockito (causs unnecessary stubbing exception
//		whenever(mockServerConfig.getIssuer()).thenReturn(issuer);
    }

    @Test
    fun getClientConfiguration_useStatic() = runBlocking {
        whenever(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient)

        val result = hybridService.getClientConfiguration(mockServerConfig)

        verify(mockStaticService).getClientConfiguration(mockServerConfig)
        verify(mockDynamicService, never()).getClientConfiguration(isA<ServerConfiguration>())
        assertEquals(mockClient, result)
    }

    @Test
    fun getClientConfiguration_useDynamic() = runBlocking {
        whenever(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(null)
        whenever(mockDynamicService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient)

        val result = hybridService.getClientConfiguration(mockServerConfig)

        verify(mockStaticService).getClientConfiguration(mockServerConfig)
        verify(mockDynamicService).getClientConfiguration(mockServerConfig)
        assertEquals(mockClient, result)
    }

    @Test
    fun getClientConfiguration_noIssuer() = runBlocking {
        // The mockServerConfig is known to both services
        // unused by mockito (causs unnecessary stubbing exception
//		whenever(mockStaticService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient);
//		whenever(mockDynamicService.getClientConfiguration(mockServerConfig)).thenReturn(mockClient);

        // But oh noes! We're going to ask it to find us some other issuer
        // unused by mockito (causs unnecessary stubbing exception

        val badIssuer = mock<ServerConfiguration>()

        //		whenever(badIssuer.getIssuer()).thenReturn("www.badexample.com");
        val result = hybridService.getClientConfiguration(badIssuer)

        verify(mockStaticService).getClientConfiguration(badIssuer)
        verify(mockDynamicService).getClientConfiguration(badIssuer)
        assertNull(result)
    }
}
