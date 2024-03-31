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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.security.authentication.AuthenticationServiceException
import javax.servlet.http.HttpServletRequest

/**
 * @author wkim
 */
class TestThirdPartyIssuerService {
    // Test fixture:
    private lateinit var request: HttpServletRequest

    private val iss = "https://server.example.org"
    private val login_hint = "I'm not telling you nothin!"
    private val target_link_uri = "https://www.example.com"
    private val redirect_uri = "https://www.example.com"

    private val accountChooserUrl = "https://www.example.com/account"

    private val service = ThirdPartyIssuerService()

    @BeforeEach
    fun prepare() {
        service.accountChooserUrl = accountChooserUrl

        request = mock<HttpServletRequest>()
        whenever(request.getParameter("iss")).thenReturn(iss)
        whenever(request.getParameter("login_hint")).thenReturn(login_hint)
        whenever(request.getParameter("target_link_uri")).thenReturn(target_link_uri)
        whenever(request.requestURL).thenReturn(StringBuffer(redirect_uri))
    }

    @Test
    fun getIssuer_hasIssuer() {
        val response = service.getIssuer(request)

        assertEquals(iss, response.issuer)
        assertEquals(login_hint, response.loginHint)
        assertEquals(target_link_uri, response.targetLinkUri)

        assertNull(response.redirectUrl)
    }

    @Test
    fun getIssuer_noIssuer() {
        whenever(request.getParameter("iss")).thenReturn(null)

        val response = service.getIssuer(request)

        assertNull(response.issuer)
        assertNull(response.loginHint)
        assertNull(response.targetLinkUri)

        // url-encoded string of the request url
        val expectedRedirectUrl = "$accountChooserUrl?redirect_uri=https%3A%2F%2Fwww.example.com"

        assertEquals(expectedRedirectUrl, response.redirectUrl)
    }

    @Test
    fun getIssuer_isWhitelisted() {
        service.whitelist = hashSetOf(iss)

        val response = service.getIssuer(request)

        assertEquals(iss, response.issuer)
        assertEquals(login_hint, response.loginHint)
        assertEquals(target_link_uri, response.targetLinkUri)

        assertNull(response.redirectUrl)
    }

    @Test
    fun getIssuer_notWhitelisted() {
        service.whitelist = hashSetOf("some.other.site")

        assertThrows<AuthenticationServiceException> {
            service.getIssuer(request)
        }
    }

    @Test
    fun getIssuer_blacklisted() {
        service.blacklist = hashSetOf(iss)

        assertThrows<AuthenticationServiceException> {
            service.getIssuer(request)
        }
    }

    @Test
    fun getIssuer_badUri() {
        whenever(request.getParameter("iss")).thenReturn(null)
        service.accountChooserUrl = "e=mc^2"

        assertThrows<AuthenticationServiceException> {
            service.getIssuer(request)
        }
    }
}
