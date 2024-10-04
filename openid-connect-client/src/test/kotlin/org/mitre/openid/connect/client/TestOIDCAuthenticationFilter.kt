package org.mitre.openid.connect.client

import io.ktor.server.auth.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock

class TestOIDCAuthenticationFilter {
    private val config: OIDCAuthenticationProvider.Config = mock {  }
    private val filter = OIDCAuthenticationProvider(config)

    @Test
    @Throws(Exception::class)
    fun attemptAuthentication_error() {
        val context = mock<AuthenticationContext>()
//        val request = mock<HttpServletRequest>()
//        whenever(request.getParameter("error")).thenReturn("Error")
//        whenever(request.getParameter("error_description")).thenReturn("Description")
//        whenever(request.getParameter("error_uri")).thenReturn("http://example.com")

        val exception = assertThrows<AuthorizationEndpointException> {
            runBlocking {
                filter.onAuthenticate(context)
            }

            Assertions.fail("AuthorizationEndpointException expected.")
        }
        assertEquals("Error from Authorization Endpoint: Error Description http://example.com", exception.message)

        assertEquals("Error", exception.error)
        assertEquals("Description", exception.errorDescription)
        assertEquals("http://example.com", exception.errorURI)
    }
}
