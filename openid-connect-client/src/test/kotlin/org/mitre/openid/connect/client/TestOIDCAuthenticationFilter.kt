package org.mitre.openid.connect.client

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class TestOIDCAuthenticationFilter {
    private val config: OIDCAuthenticationProvider.Config = mock {  }
    private val filter = OIDCAuthenticationProvider(config)

    @Test
    @Throws(Exception::class)
    fun attemptAuthentication_error() {
        val request = mock<ApplicationRequest> {
            whenever(mock.queryParameters).thenReturn(parameters {
                append("error", "Error")
                append("error_description", "Description")
                append("error_uri", "http://example.com")
            })
        }
        val call = mock<ApplicationCall> {
            whenever(mock.request).thenReturn(request)
        }
        val context = mock<AuthenticationContext> {
            whenever(mock.call).thenReturn(call)
        }

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
