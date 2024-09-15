package io.github.pdvrieze.auth.service.impl

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.exception.InvalidRequestException
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.whenever

/**
 * @author jricher
 */
@ExtendWith(MockitoExtension::class)
class TestKtorBlacklistAwareRedirectResolver {
    @Mock
    private lateinit var blacklistService: BlacklistedSiteService

    @Mock
    private lateinit var client: OAuthClientDetails

    @Mock
    private lateinit var config: ConfigurationPropertiesBean

    @InjectMocks
    private lateinit var resolver: BlacklistAwareRedirectResolver

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
