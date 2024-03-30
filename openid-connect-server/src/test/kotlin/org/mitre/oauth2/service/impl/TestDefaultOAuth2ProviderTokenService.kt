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
package org.mitre.oauth2.service.impl

import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mockito.AdditionalAnswers
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.isA
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import java.util.*

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestDefaultOAuth2ProviderTokenService {
    // Test Fixture:
    private lateinit var authentication: OAuth2Authentication
    private lateinit var client: ClientDetailsEntity
    private lateinit var badClient: ClientDetailsEntity
    private lateinit var refreshToken: OAuth2RefreshTokenEntity
    private lateinit var accessToken: OAuth2AccessTokenEntity
    private lateinit var tokenRequest: TokenRequest

    // for use when refreshing access tokens
    private lateinit var storedAuthRequest: OAuth2Request
    private lateinit var storedAuthentication: OAuth2Authentication
    private lateinit var storedAuthHolder: AuthenticationHolderEntity
    private lateinit var storedScope: Set<String>

    @Mock
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    private lateinit var authenticationHolderRepository: AuthenticationHolderRepository

    @Mock
    private lateinit var clientDetailsService: ClientDetailsEntityService

    @Mock
    private lateinit var tokenEnhancer: TokenEnhancer

    @Mock
    private lateinit var scopeService: SystemScopeService

    @InjectMocks
    private lateinit var service: DefaultOAuth2ProviderTokenService

    /**
     * Set up a mock authentication and mock client to work with.
     */
    @BeforeEach
    fun prepare() {
        Mockito.reset(tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer)

        authentication = Mockito.mock(OAuth2Authentication::class.java)
        val clientAuth = OAuth2Request(null, clientId, null, true, scope, null, null, null, null)
        whenever(authentication.getOAuth2Request()) doReturn (clientAuth)

        client = Mockito.mock(ClientDetailsEntity::class.java)
        whenever(client.getClientId()) doReturn (clientId)
        whenever(clientDetailsService.loadClientByClientId(clientId)) doReturn (client)
        whenever(client.isReuseRefreshToken) doReturn (true)

        // by default in tests, allow refresh tokens
        whenever(client.isAllowRefresh) doReturn (true)

        // by default, clear access tokens on refresh
        whenever(client.isClearAccessTokensOnRefresh) doReturn (true)

        badClient = Mockito.mock(ClientDetailsEntity::class.java)
        whenever(badClient.getClientId()) doReturn (badClientId)
        whenever(clientDetailsService.loadClientByClientId(badClientId)) doReturn (badClient)

        refreshToken = Mockito.mock(OAuth2RefreshTokenEntity::class.java)
        whenever(tokenRepository.getRefreshTokenByValue(refreshTokenValue)) doReturn (refreshToken)
        whenever(refreshToken.client) doReturn (client)
        whenever(refreshToken.isExpired) doReturn (false)

        accessToken = Mockito.mock(OAuth2AccessTokenEntity::class.java)

        tokenRequest = TokenRequest(null, clientId, null, null)

        storedAuthentication = authentication
        storedAuthRequest = clientAuth
        storedAuthHolder = Mockito.mock(AuthenticationHolderEntity::class.java)
        storedScope = scope.toHashSet()

        whenever(refreshToken.authenticationHolder) doReturn (storedAuthHolder)
        whenever(storedAuthHolder.authentication) doReturn (storedAuthentication)
        whenever(storedAuthentication.oAuth2Request) doReturn (storedAuthRequest)

        whenever(authenticationHolderRepository.save(isA())) doReturn (storedAuthHolder)

        whenever(scopeService.fromStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val args = invocation.arguments
            val input = args[0] as Set<String>
            val output: MutableSet<SystemScope> = HashSet()
            for (scope in input) {
                output.add(SystemScope(scope))
            }
            output
        }

        whenever(scopeService.toStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val args = invocation.arguments
            val input = args[0] as Set<SystemScope>
            val output: MutableSet<String?> = HashSet()
            for (scope in input) {
                output.add(scope.value)
            }
            output
        }

        // we're not testing restricted or reserved scopes here, just pass through
        whenever(scopeService.removeReservedScopes(ArgumentMatchers.anySet()))
            .then(AdditionalAnswers.returnsFirstArg<Any>())

        // unused by mockito (causs unnecessary stubbing exception
//		when(scopeService.removeRestrictedAndReservedScopes(anySet())).then(returnsFirstArg());
        whenever(tokenEnhancer.enhance(isA<OAuth2AccessTokenEntity>(), isA<OAuth2Authentication>()))
            .thenAnswer { invocation ->
                val args = invocation.arguments
                args[0] as OAuth2AccessTokenEntity
            }

        whenever(tokenRepository.saveAccessToken(isA<OAuth2AccessTokenEntity>())).thenAnswer {
            invocation ->
                val args = invocation.arguments
                args[0] as OAuth2AccessTokenEntity
            }

        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer { invocation ->
                val args = invocation.arguments
                args[0] as OAuth2RefreshTokenEntity
            }
    }

    /**
     * Tests exception handling for null authentication or null authorization.
     */
    @Test
    fun createAccessToken_nullAuth() {
        whenever(authentication.oAuth2Request) doReturn (null)

        assertThrows<AuthenticationCredentialsNotFoundException> {
            service.createAccessToken(null)
        }

        assertThrows<AuthenticationCredentialsNotFoundException> {
            service.createAccessToken(authentication)
        }
    }

    /**
     * Tests exception handling for clients not found.
     */
    @Test
    fun createAccessToken_nullClient() {
        whenever(clientDetailsService.loadClientByClientId(ArgumentMatchers.anyString())) doReturn (null)

        assertThrows<InvalidClientException> {
            service.createAccessToken(authentication)
        }
    }

    /**
     * Tests the creation of access tokens for clients that are not allowed to have refresh tokens.
     */
    @Test
    fun createAccessToken_noRefresh() {
        whenever(client.isAllowRefresh) doReturn (false)

        val token = service.createAccessToken(authentication)

        verify(clientDetailsService).loadClientByClientId(ArgumentMatchers.anyString())
        verify(authenticationHolderRepository)
            .save(isA<AuthenticationHolderEntity>())
        verify(tokenEnhancer)
            .enhance(isA<OAuth2AccessTokenEntity>(), eq(authentication))
        verify(tokenRepository).saveAccessToken(isA<OAuth2AccessTokenEntity>())
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        verify(tokenRepository, Mockito.never())
            .saveRefreshToken(isA<OAuth2RefreshTokenEntity>())

        assertThat(token.refreshToken, CoreMatchers.`is`(CoreMatchers.nullValue()))
    }

    /**
     * Tests the creation of access tokens for clients that are allowed to have refresh tokens.
     */
    @Test
    fun createAccessToken_yesRefresh() {
        val clientAuth =
            OAuth2Request(null, clientId, null, true, hashSetOf(SystemScopeService.OFFLINE_ACCESS), null, null, null, null)
        whenever(authentication.oAuth2Request) doReturn (clientAuth)
        whenever(client.isAllowRefresh) doReturn (true)

        val token = service.createAccessToken(authentication)

        // Note: a refactor may be appropriate to only save refresh tokens once to the repository during creation.
        verify(tokenRepository, Mockito.atLeastOnce())
            .saveRefreshToken(isA<OAuth2RefreshTokenEntity>())
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.refreshToken, CoreMatchers.`is`(CoreMatchers.notNullValue()))
    }

    /**
     * Checks to see that the expiration date of new tokens is being set accurately to within some delta for time skew.
     */
    @Test
    fun createAccessToken_expiration() {
        val accessTokenValiditySeconds = 3600
        val refreshTokenValiditySeconds = 600

        whenever(client.accessTokenValiditySeconds) doReturn (accessTokenValiditySeconds)
        whenever(client.refreshTokenValiditySeconds) doReturn (refreshTokenValiditySeconds)

        val start = System.currentTimeMillis()
        val token = service.createAccessToken(authentication)
        val end = System.currentTimeMillis()

        // Accounting for some delta for time skew on either side.
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA)
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA)
        val lowerBoundRefreshTokens = Date(start + (refreshTokenValiditySeconds * 1000L) - DELTA)
        val upperBoundRefreshTokens = Date(end + (refreshTokenValiditySeconds * 1000L) + DELTA)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertTrue(
            token.expiration!!.after(lowerBoundAccessTokens) && token.expiration!!
                .before(upperBoundAccessTokens)
        )
        assertTrue(token.refreshToken!!.expiration!!.after(lowerBoundRefreshTokens) && token.refreshToken!!.expiration!!.before(upperBoundRefreshTokens))
    }

    @Test
    fun createAccessToken_checkClient() {
        val token = service.createAccessToken(authentication)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.client!!.clientId, CoreMatchers.equalTo(clientId))
    }

    @Test
    fun createAccessToken_checkScopes() {
        val token = service.createAccessToken(authentication)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.scope, CoreMatchers.equalTo(scope))
    }

    @Test
    fun createAccessToken_checkAttachedAuthentication() {
        val authHolder = Mockito.mock(AuthenticationHolderEntity::class.java)
        whenever(authHolder.authentication) doReturn (authentication)

        whenever(authenticationHolderRepository.save(isA<AuthenticationHolderEntity>())) doReturn (authHolder)

        val token = service.createAccessToken(authentication)

        assertThat(token.authenticationHolder.authentication, CoreMatchers.equalTo(authentication))
        verify(authenticationHolderRepository)
            .save(isA<AuthenticationHolderEntity>())
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_noRefreshToken() {
        whenever(tokenRepository.getRefreshTokenByValue(ArgumentMatchers.anyString())) doReturn (null)

        assertThrows<InvalidTokenException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_notAllowRefresh() {
        whenever(client.isAllowRefresh) doReturn (false)

        assertThrows<InvalidClientException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_clientMismatch() {
        tokenRequest = TokenRequest(null, badClientId, null, null)

        assertThrows<InvalidClientException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_expired() {
        whenever(refreshToken.isExpired) doReturn (true)

        assertThrows<InvalidTokenException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_verifyAcessToken() {
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository).clearAccessTokensForRefreshToken(refreshToken)

        assertThat(token.client, CoreMatchers.equalTo(client))
        assertThat(token.refreshToken, CoreMatchers.equalTo(refreshToken))
        assertThat(token.authenticationHolder, CoreMatchers.equalTo(storedAuthHolder))

        verify(tokenEnhancer).enhance(token, storedAuthentication)
        verify(tokenRepository).saveAccessToken(token)
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_rotateRefreshToken() {
        whenever(client.isReuseRefreshToken) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository).clearAccessTokensForRefreshToken(refreshToken)

        assertThat(token.client, CoreMatchers.equalTo(client))
        assertThat(token.refreshToken, CoreMatchers.not(CoreMatchers.equalTo(refreshToken)))
        assertThat(token.authenticationHolder, CoreMatchers.equalTo(storedAuthHolder))

        verify(tokenEnhancer).enhance(token, storedAuthentication)
        verify(tokenRepository).saveAccessToken(token)
        verify(tokenRepository).removeRefreshToken(refreshToken)
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_keepAccessTokens() {
        whenever(client.isClearAccessTokensOnRefresh) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository, Mockito.never()).clearAccessTokensForRefreshToken(refreshToken)

        assertThat(token.client, CoreMatchers.equalTo(client))
        assertThat(token.refreshToken, CoreMatchers.equalTo(refreshToken))
        assertThat(token.authenticationHolder, CoreMatchers.equalTo(storedAuthHolder))

        verify(tokenEnhancer).enhance(token, storedAuthentication)
        verify(tokenRepository).saveAccessToken(token)
        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_requestingSameScope() {
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.scope, CoreMatchers.equalTo(storedScope))
    }

    @Test
    fun refreshAccessToken_requestingLessScope() {
        val lessScope: Set<String> = hashSetOf("openid", "profile")

        tokenRequest.setScope(lessScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.scope, CoreMatchers.equalTo(lessScope))
    }

    @Test
    fun refreshAccessToken_requestingMoreScope() {
        val moreScope = storedScope + setOf("address", "phone")

        tokenRequest.setScope(moreScope)

        assertThrows<InvalidScopeException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    /**
     * Tests the case where only some of the valid scope values are being requested along with
     * other extra unauthorized scope values.
     */
    @Test
    fun refreshAccessToken_requestingMixedScope() {
        val mixedScope: Set<String> =
            setOf("openid", "profile", "address", "phone") // no email or offline_access

        tokenRequest.setScope(mixedScope)

        assertThrows<InvalidScopeException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_requestingEmptyScope() {
        val emptyScope: Set<String> = hashSetOf()

        tokenRequest.setScope(emptyScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.scope, CoreMatchers.equalTo(storedScope))
    }

    @Test
    fun refreshAccessToken_requestingNullScope() {
        tokenRequest.setScope(null)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertThat(token.scope, CoreMatchers.equalTo(storedScope))
    }

    /**
     * Checks to see that the expiration date of refreshed tokens is being set accurately to within some delta for time skew.
     */
    @Test
    fun refreshAccessToken_expiration() {
        val accessTokenValiditySeconds = 3600

        whenever(client.accessTokenValiditySeconds) doReturn (accessTokenValiditySeconds)

        val start = System.currentTimeMillis()
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)
        val end = System.currentTimeMillis()

        // Accounting for some delta for time skew on either side.
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA)
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA)

        verify(scopeService, Mockito.atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        assertTrue(
            token.expiration!!.after(lowerBoundAccessTokens) && token.expiration!!
                .before(upperBoundAccessTokens)
        )
    }

    @Test
    fun getAllAccessTokensForUser() {
        whenever<Set<OAuth2AccessTokenEntity?>>(tokenRepository.getAccessTokensByUserName(userName)) doReturn(hashSetOf(accessToken))

        val tokens: Set<OAuth2AccessTokenEntity?> = service.getAllAccessTokensForUser(userName)
        assertEquals(1, tokens.size)
        assertTrue(tokens.contains(accessToken))
    }

    @Test
    fun getAllRefreshTokensForUser() {
        whenever<Set<OAuth2RefreshTokenEntity?>>(tokenRepository.getRefreshTokensByUserName(userName)) doReturn(hashSetOf(refreshToken))

        val tokens: Set<OAuth2RefreshTokenEntity?> = service.getAllRefreshTokensForUser(userName)
        assertEquals(1, tokens.size)
        assertTrue(tokens.contains(refreshToken))
    }

    companion object {
        // Grace period for time-sensitive tests.
        private const val DELTA = 100L
        private val refreshTokenValue = "refresh_token_value"
        private val userName = "6a50ac11786d402a9591d3e592ac770f"
        private val clientId = "test_client"
        private val badClientId = "bad_client"
        private val scope: Set<String> = hashSetOf("openid", "profile", "email", "offline_access")
    }
}