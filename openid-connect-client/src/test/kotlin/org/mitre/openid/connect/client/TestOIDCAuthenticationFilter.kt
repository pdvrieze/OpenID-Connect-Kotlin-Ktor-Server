package org.mitre.openid.connect.client

import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.security.authentication.AuthenticationServiceException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class TestOIDCAuthenticationFilter {
    private val filter = OIDCAuthenticationFilter()

    @Test
    @Throws(Exception::class)
    fun attemptAuthentication_error() {
        val request = Mockito.mock(HttpServletRequest::class.java)
        Mockito.`when`(request.getParameter("error")).thenReturn("Error")
        Mockito.`when`(request.getParameter("error_description")).thenReturn("Description")
        Mockito.`when`(request.getParameter("error_uri")).thenReturn("http://example.com")

        try {
            filter.attemptAuthentication(request, Mockito.mock(HttpServletResponse::class.java))

            Assertions.fail("AuthorizationEndpointException expected.")
        } catch (exception: AuthorizationEndpointException) {
            MatcherAssert.assertThat(
                exception.message,
                CoreMatchers.`is`("Error from Authorization Endpoint: Error Description http://example.com")
            )

            MatcherAssert.assertThat(exception.error, CoreMatchers.`is`("Error"))
            MatcherAssert.assertThat(exception.errorDescription, CoreMatchers.`is`("Description"))
            MatcherAssert.assertThat(exception.errorURI, CoreMatchers.`is`("http://example.com"))

            MatcherAssert.assertThat(exception, CoreMatchers.`is`(CoreMatchers.instanceOf(AuthenticationServiceException::class.java)))
        }
    }
}
