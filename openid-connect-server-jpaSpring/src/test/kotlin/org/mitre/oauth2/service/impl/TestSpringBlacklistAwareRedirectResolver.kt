/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.oauth2.service.impl

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestSpringBlacklistAwareRedirectResolver {
    @Mock
    private lateinit var blacklistService: BlacklistedSiteService

    @Mock
    private lateinit var client: OAuthClientDetails

    @Mock
    private lateinit var config: ConfigurationPropertiesBean

    @InjectMocks
    private lateinit var resolver: SpringBlacklistAwareRedirectResolver

    private val blacklistedUri = "https://evil.example.com/"

    private val goodUri = "https://good.example.com/"

    private val pathUri = "https://good.example.com/with/path"

    @Test
    fun testResolveRedirect_safe() {
        whenever(blacklistService.isBlacklisted(ArgumentMatchers.anyString())) doReturn false

        whenever(client.authorizedGrantTypes) doReturn setOf("authorization_code")
        whenever(client.registeredRedirectUri) doReturn setOf(goodUri, blacklistedUri)

        whenever(config.isHeartMode) doReturn false

        // default uses prefix matching, the first one should work fine
        Assertions.assertEquals(goodUri, resolver.resolveRedirect(goodUri, client))


        // set the resolver to non-strict and test the path-based redirect resolution
        resolver.isStrictMatch = false

        Assertions.assertEquals(pathUri, resolver.resolveRedirect(pathUri, client))
    }

    @Test
    fun testResolveRedirect_blacklisted() {
        whenever(blacklistService.isBlacklisted(ArgumentMatchers.anyString())) doReturn false

        whenever(blacklistService.isBlacklisted(blacklistedUri)) doReturn true

        whenever(client.authorizedGrantTypes) doReturn setOf("authorization_code")
        whenever(client.registeredRedirectUri) doReturn setOf(goodUri, blacklistedUri)

        whenever(config.isHeartMode) doReturn false

        // this should fail with an error
        assertThrows<InvalidRequestException> {
            resolver.resolveRedirect(blacklistedUri, client)
        }
    }

    @Test
    fun testRedirectMatches_default() {
        whenever(config.isHeartMode) doReturn false

        // this is not an exact match
        Assertions.assertFalse(resolver.redirectMatches(pathUri, goodUri))

        // this is an exact match
        Assertions.assertTrue(resolver.redirectMatches(goodUri, goodUri))
    }

    @Test
    fun testRedirectMatches_nonstrict() {
        whenever(config.isHeartMode) doReturn false

        // set the resolver to non-strict match mode

        resolver.isStrictMatch = false


        // this is not an exact match (but that's OK)
        Assertions.assertTrue(resolver.redirectMatches(pathUri, goodUri))

        // this is an exact match
        Assertions.assertTrue(resolver.redirectMatches(goodUri, goodUri))
    }

    @Test
    fun testHeartMode() {
        whenever(config.isHeartMode) doReturn (true)

        // this is not an exact match
        Assertions.assertFalse(resolver.redirectMatches(pathUri, goodUri))

        // this is an exact match
        Assertions.assertTrue(resolver.redirectMatches(goodUri, goodUri))
    }
}
