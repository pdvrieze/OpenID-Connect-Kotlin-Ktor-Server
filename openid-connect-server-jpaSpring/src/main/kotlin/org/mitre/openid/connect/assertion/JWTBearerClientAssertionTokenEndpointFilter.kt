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
package org.mitre.openid.connect.assertion

import com.nimbusds.jwt.JWTParser
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.RequestMatcher
import java.io.IOException
import java.text.ParseException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Filter to check client authentication via JWT Bearer assertions.
 *
 * @author jricher
 */
class JWTBearerClientAssertionTokenEndpointFilter(additionalMatcher: RequestMatcher) :
    AbstractAuthenticationProcessingFilter(ClientAssertionRequestMatcher(additionalMatcher)) {
    private val authenticationEntryPoint: AuthenticationEntryPoint = OAuth2AuthenticationEntryPoint()

    init {
        // If authentication fails the type is "Form"
        (authenticationEntryPoint as OAuth2AuthenticationEntryPoint).setTypeName("Form")
    }

    override fun afterPropertiesSet() {
        super.afterPropertiesSet()
        setAuthenticationFailureHandler { request, response, exception ->
            var exception = exception
            if (exception is BadCredentialsException) {
                exception = BadCredentialsException(exception.message, BadClientCredentialsException())
            }
            authenticationEntryPoint.commence(request, response, exception)
        }
        setAuthenticationSuccessHandler { request, response, authentication ->
            // no-op - just allow filter chain to continue to token endpoint
        }
    }

    /**
     * Pull the assertion out of the request and send it up to the auth manager for processing.
     */
    @Throws(AuthenticationException::class, IOException::class, ServletException::class)
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        // check for appropriate parameters

        val assertionType = request.getParameter("client_assertion_type")
        val assertion = request.getParameter("client_assertion")

        try {
            val jwt = JWTParser.parse(assertion)

            val clientId = jwt.jwtClaimsSet.subject

            val authRequest: Authentication =
                JWTBearerAssertionAuthenticationToken(jwt)

            return authenticationManager.authenticate(authRequest)
        } catch (e: ParseException) {
            throw BadCredentialsException("Invalid JWT credential: $assertion")
        }
    }

    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(
        request: HttpServletRequest, response: HttpServletResponse,
        chain: FilterChain, authResult: Authentication
    ) {
        super.successfulAuthentication(request, response, chain, authResult)
        chain.doFilter(request, response)
    }

    private class ClientAssertionRequestMatcher(private val additionalMatcher: RequestMatcher) : RequestMatcher {
        override fun matches(request: HttpServletRequest): Boolean {
            // check for appropriate parameters
            val assertionType = request.getParameter("client_assertion_type")
            val assertion = request.getParameter("client_assertion")

            if (assertionType.isNullOrEmpty() || assertion.isNullOrEmpty()) {
                return false
            } else if (assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
                return false
            }

            return additionalMatcher.matches(request)
        }
    }
}
