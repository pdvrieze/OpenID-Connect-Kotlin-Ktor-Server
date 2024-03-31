package org.mitre.openid.connect.client

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class TestOIDCAuthenticationFilter {
    private val filter = OIDCAuthenticationFilter()

    @Test
    @Throws(Exception::class)
    fun attemptAuthentication_error() {
        val request = mock<HttpServletRequest>()
        whenever(request.getParameter("error")).thenReturn("Error")
        whenever(request.getParameter("error_description")).thenReturn("Description")
        whenever(request.getParameter("error_uri")).thenReturn("http://example.com")

        val exception = assertThrows<AuthorizationEndpointException> {
            filter.attemptAuthentication(request, mock<HttpServletResponse>())

            Assertions.fail("AuthorizationEndpointException expected.")
        }
        assertEquals("Error from Authorization Endpoint: Error Description http://example.com", exception.message)

        assertEquals("Error", exception.error)
        assertEquals("Description", exception.errorDescription)
        assertEquals("http://example.com", exception.errorURI)
    }
}
