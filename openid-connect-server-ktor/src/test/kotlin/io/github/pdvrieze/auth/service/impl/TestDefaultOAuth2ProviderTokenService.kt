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
package io.github.pdvrieze.auth.service.impl

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.exception.InvalidScopeException
import org.mitre.oauth2.exception.InvalidTokenException
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2Authentication
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.token.ConnectTokenEnhancer
import org.mockito.AdditionalAnswers
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.ArgumentMatchers.anySet
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.any
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.eq
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.reset
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import java.util.*
import kotlin.collections.HashSet

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
    private lateinit var tokenRequest: OAuth2Request

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
    private lateinit var tokenEnhancer: ConnectTokenEnhancer

    @Mock
    private lateinit var scopeService: SystemScopeService

    @Mock
    private lateinit var approvedSiteService: ApprovedSiteService

    private lateinit var service: DefaultOAuth2ProviderTokenService

    /**
     * Set up a mock authentication and mock client to work with.
     */
    @BeforeEach
    fun prepare() {
        reset(tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer)

        service = DefaultOAuth2ProviderTokenService(
            tokenRepository = tokenRepository,
            authenticationHolderRepository = authenticationHolderRepository,
            clientDetailsService = clientDetailsService,
            tokenEnhancer = tokenEnhancer,
            scopeService = scopeService,
            approvedSiteService = approvedSiteService,
        )

        authentication = mock<OAuth2Authentication>()
        val clientAuth = OAuth2Request(
            clientId = clientId,
            isApproved = true,
            scope = scope,
        )
        whenever(authentication.oAuth2Request) doReturn (clientAuth)

        client = mock<ClientDetailsEntity>()
        whenever(client.clientId) doReturn (clientId)
        whenever(clientDetailsService.loadClientByClientId(clientId)) doReturn (client)
        whenever(client.isReuseRefreshToken) doReturn (true)

        // by default in tests, allow refresh tokens
        whenever(client.isAllowRefresh) doReturn (true)

        // by default, clear access tokens on refresh
        whenever(client.isClearAccessTokensOnRefresh) doReturn (true)

        badClient = mock<ClientDetailsEntity>()
        whenever(badClient.clientId) doReturn (badClientId)
        whenever(clientDetailsService.loadClientByClientId(badClientId)) doReturn (badClient)

        refreshToken = mock<OAuth2RefreshTokenEntity>()
        whenever(tokenRepository.getRefreshTokenByValue(refreshTokenValue)) doReturn (refreshToken)
        whenever(refreshToken.client) doReturn (client)
        whenever(refreshToken.isExpired) doReturn (false)

        accessToken = mock<OAuth2AccessTokenEntity>()

        tokenRequest = OAuth2Request(clientId = clientId)

        storedAuthentication = authentication
        storedAuthRequest = clientAuth
        storedAuthHolder = mock<AuthenticationHolderEntity>()
        storedScope = scope.toHashSet()

        whenever(refreshToken.authenticationHolder) doReturn (storedAuthHolder)
        whenever(storedAuthHolder.authentication) doReturn (storedAuthentication)
        whenever(storedAuthentication.oAuth2Request) doReturn (storedAuthRequest)

        whenever(authenticationHolderRepository.save(isA())) doReturn (storedAuthHolder)

        whenever(scopeService.fromStrings(anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<String>
            input.mapTo(HashSet()) { SystemScope(it) }
        }

        whenever(scopeService.toStrings(anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<SystemScope>
            input.mapTo(HashSet()) { it.value }
        }

        // we're not testing restricted or reserved scopes here, just pass through
        whenever(scopeService.removeReservedScopes(anySet()))
            .then(AdditionalAnswers.returnsFirstArg<Any>())

        // unused by mockito (causs unnecessary stubbing exception
//		when(scopeService.removeRestrictedAndReservedScopes(anySet())).then(returnsFirstArg());
        whenever(tokenEnhancer.enhance(isA<OAuth2AccessTokenEntity.Builder>(), isA<OAuth2Authentication>()))
            .thenAnswer { invocation ->
                Unit
//                val args = invocation.arguments
//                args[0] as OAuth2AccessTokenEntity
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
        TODO("Probably invalid")
/*
        whenever(authentication.oAuth2Request) doReturn (OAuth2Request(clientId = "dummy"))

        assertThrows<AuthenticationCredentialsNotFoundException> {
            service.createAccessToken(null)
        }

        assertThrows<AuthenticationCredentialsNotFoundException> {
            service.createAccessToken(authentication)
        }
*/
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
        verify(authenticationHolderRepository).save(isA<AuthenticationHolderEntity>())
        verify(tokenEnhancer).enhance(isA<OAuth2AccessTokenEntity.Builder>(), eq(authentication))
        verify(tokenRepository).saveAccessToken(isA<OAuth2AccessTokenEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        verify(tokenRepository, never()).saveRefreshToken(isA<OAuth2RefreshTokenEntity>())

        assertNull(token.refreshToken)
    }

    /**
     * Tests the creation of access tokens for clients that are allowed to have refresh tokens.
     */
    @Test
    fun createAccessToken_yesRefresh() {
        val clientAuth = OAuth2Request(
            clientId = clientId,
            isApproved = true,
            scope = hashSetOf(SystemScopeService.OFFLINE_ACCESS),
        )
        whenever(authentication.oAuth2Request) doReturn (clientAuth)
        whenever(client.isAllowRefresh) doReturn (true)
        lateinit var refreshToken: OAuth2RefreshTokenEntity
        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>())) doAnswer { mock ->
            (mock.arguments[0] as OAuth2RefreshTokenEntity).also {
                it.id = it.id ?: 42L
                refreshToken = it
            }
        }

        whenever(tokenRepository.getRefreshTokenById(anyLong())).doAnswer {
            refreshToken
        }

        val token = service.createAccessToken(authentication)

        verify(tokenRepository, atLeastOnce()).getRefreshTokenById(anyLong())

        // Note: a refactor may be appropriate to only save refresh tokens once to the repository during creation.
        verify(tokenRepository, atLeastOnce()).saveRefreshToken(isA<OAuth2RefreshTokenEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertNotNull(token.refreshToken)
        assertEquals(refreshToken, token.refreshToken)
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
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA).toInstant()
        val lowerBoundRefreshTokens = Date(start + (refreshTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundRefreshTokens = Date(end + (refreshTokenValiditySeconds * 1000L) + DELTA).toInstant()

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertTrue(token.expirationInstant.isAfter(lowerBoundAccessTokens))
        assertTrue(token.expirationInstant.isBefore(upperBoundAccessTokens))

        val rt = token.refreshToken
        assertNotNull(rt)
        val exp = rt!!.expirationInstant
        assertTrue(exp.isAfter(lowerBoundRefreshTokens))
        assertTrue(exp.isBefore(upperBoundRefreshTokens))
    }

    @Test
    fun createAccessToken_checkClient() {
        val token: OAuth2AccessToken = service.createAccessToken(authentication)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(clientId, token.client!!.clientId)
    }

    @Test
    fun createAccessToken_checkScopes() {
        val token = service.createAccessToken(authentication)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(scope, token.scope)
    }

    @Test
    fun createAccessToken_checkAttachedAuthentication() {
        val authHolder = mock<AuthenticationHolderEntity>()
        whenever(authHolder.authentication) doReturn (authentication)

        whenever(authenticationHolderRepository.save(isA<AuthenticationHolderEntity>())) doReturn (authHolder)

        val token = service.createAccessToken(authentication)

        assertEquals(authentication, token.authenticationHolder.authentication)
        verify(authenticationHolderRepository).save(isA<AuthenticationHolderEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())
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
        tokenRequest = OAuth2Request(clientId= badClientId)

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

        assertEquals(client, token.client)
        assertEquals(refreshToken, token.refreshToken)
        assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(token.builder(), storedAuthentication)
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())
    }

    @Test
    fun refreshAccessToken_rotateRefreshToken() {
        whenever(client.isReuseRefreshToken) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository).clearAccessTokensForRefreshToken(refreshToken)

        assertEquals(client, token.client)
        assertNotEquals(refreshToken, token.refreshToken)
        assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(token.builder(), storedAuthentication)
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(tokenRepository).removeRefreshToken(refreshToken)
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())
    }

    @Test
    fun refreshAccessToken_keepAccessTokens() {
        whenever(client.isClearAccessTokensOnRefresh) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository, never()).clearAccessTokensForRefreshToken(refreshToken)

        assertEquals(client, token.client)
        assertEquals(refreshToken, token.refreshToken)
        assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(token.builder(), storedAuthentication)
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())
    }

    @Test
    fun refreshAccessToken_requestingSameScope() {
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(storedScope, token.scope)
    }

    @Test
    fun refreshAccessToken_requestingLessScope() {
        val lessScope: Set<String> = hashSetOf("openid", "profile")

        tokenRequest = tokenRequest.copy(scope = lessScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(lessScope, token.scope)
    }

    @Test
    fun refreshAccessToken_requestingMoreScope() {
        val moreScope = storedScope + setOf("address", "phone")

        tokenRequest = tokenRequest.copy(scope=moreScope)

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

        tokenRequest = tokenRequest.copy(scope = mixedScope)

        assertThrows<InvalidScopeException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_requestingEmptyScope() {
        val emptyScope: Set<String> = hashSetOf()

        tokenRequest = tokenRequest.copy(scope = emptyScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(storedScope, token.scope)
    }

/*
    @Test
    fun refreshAccessToken_requestingNullScope() {
        tokenRequest = tokenRequest.copy(scope = emptySet())

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertEquals(storedScope, token.scope)
    }
*/

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
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA).toInstant()

        verify(scopeService, atLeastOnce()).removeReservedScopes(anySet())

        assertTrue(token.expirationInstant.isAfter(lowerBoundAccessTokens))

        assertTrue(token.expirationInstant.isBefore(upperBoundAccessTokens))
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
