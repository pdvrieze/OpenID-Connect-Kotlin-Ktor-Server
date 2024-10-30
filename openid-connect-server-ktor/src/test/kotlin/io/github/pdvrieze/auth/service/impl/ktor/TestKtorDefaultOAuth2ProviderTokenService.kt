package io.github.pdvrieze.auth.service.impl.ktor

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.exception.InvalidScopeException
import org.mitre.oauth2.exception.InvalidTokenException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.token.ConnectTokenEnhancer
import org.mockito.AdditionalAnswers
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.any
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.atMost
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

/**
 * @author wkim
 */
@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestKtorDefaultOAuth2ProviderTokenService {
    // Test Fixture:
    private lateinit var authentication: AuthenticatedAuthorizationRequest
    private lateinit var client: ClientDetailsEntity
    private lateinit var badClient: ClientDetailsEntity
    private lateinit var refreshToken: OAuth2RefreshTokenEntity
    private lateinit var accessToken: OAuth2AccessTokenEntity
    private lateinit var tokenRequest: AuthorizationRequest

    // for use when refreshing access tokens
    private lateinit var storedAuthRequest: AuthorizationRequest
    private lateinit var storedAuthentication: AuthenticatedAuthorizationRequest
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
    fun prepare(): Unit = runBlocking {
        reset(tokenRepository, authenticationHolderRepository, clientDetailsService, tokenEnhancer)

        service = DefaultOAuth2ProviderTokenService(
            tokenRepository = tokenRepository,
            authenticationHolderRepository = authenticationHolderRepository,
            clientDetailsService = clientDetailsService,
            tokenEnhancer = tokenEnhancer,
            scopeService = scopeService,
            approvedSiteService = approvedSiteService,
        )

        authentication = mock<AuthenticatedAuthorizationRequest>()
        val clientAuth = AuthorizationRequest(
            clientId = clientId,
            isApproved = true,
            scope = scope,
            requestTime = xxxx,
        )
        whenever(authentication.authorizationRequest) doReturn (clientAuth)

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
        whenever(tokenRepository.getRefreshTokenById(43)) doReturn (refreshToken)
        whenever(refreshToken.client) doReturn (client)
        whenever(refreshToken.isExpired) doReturn (false)
        whenever(refreshToken.id) doReturn 43

        accessToken = mock<OAuth2AccessTokenEntity>()

        tokenRequest = AuthorizationRequest(clientId = clientId, requestTime = xxxx)

        storedAuthentication = authentication
        storedAuthRequest = clientAuth
        storedAuthHolder = mock<AuthenticationHolderEntity>()
        storedScope = scope.toHashSet()

        whenever(refreshToken.authenticationHolder) doReturn (storedAuthHolder)
        whenever(storedAuthHolder.authenticatedAuthorizationRequest) doReturn (storedAuthentication)
        whenever(storedAuthHolder.id) doReturn (33)
        whenever(storedAuthentication.authorizationRequest) doReturn (storedAuthRequest)

        whenever(authenticationHolderRepository.save(isA())) doReturn (storedAuthHolder)
        whenever(authenticationHolderRepository.getById(33)) doReturn (storedAuthHolder)

        whenever(scopeService.fromStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<String>
            input.mapTo(HashSet()) { SystemScope(it) }
        }

        whenever(scopeService.toStrings(ArgumentMatchers.anySet())).thenAnswer { invocation ->
            val input = invocation.arguments[0] as Set<SystemScope>
            input.mapTo(HashSet()) { it.value }
        }

        // we're not testing restricted or reserved scopes here, just pass through
        whenever(scopeService.removeReservedScopes(ArgumentMatchers.anySet()))
            .then(AdditionalAnswers.returnsFirstArg<Any>())

        // unused by mockito (causs unnecessary stubbing exception
//		when(scopeService.removeRestrictedAndReservedScopes(anySet())).then(returnsFirstArg());
        whenever(tokenEnhancer.enhance(isA<OAuth2AccessTokenEntity.Builder>(), isA<AuthenticatedAuthorizationRequest>()))
            .thenAnswer { invocation ->
                Unit
//                val args = invocation.arguments
//                args[0] as OAuth2AccessTokenEntity
            }

        whenever(tokenRepository.saveAccessToken(isA<OAuth2AccessTokenEntity>())).thenAnswer { invocation ->
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
    @Disabled
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
    fun createAccessToken_nullClient(): Unit = runBlocking {
        whenever(clientDetailsService.loadClientByClientId(ArgumentMatchers.anyString())) doReturn (null)

        assertThrows<InvalidClientException> {
            service.createAccessToken(authentication, xxx)
        }
    }

    /**
     * Tests the creation of access tokens for clients that are not allowed to have refresh tokens.
     */
    @Test
    fun createAccessToken_noRefresh(): Unit = runBlocking {
        whenever(client.isAllowRefresh) doReturn (false)

        val token = service.createAccessToken(authentication, xxx)

        verify(clientDetailsService).loadClientByClientId(ArgumentMatchers.anyString())
        verify(authenticationHolderRepository).save(isA<AuthenticationHolderEntity>())
        verify(tokenEnhancer).enhance(isA<OAuth2AccessTokenEntity.Builder>(), eq(authentication))
        verify(tokenRepository).saveAccessToken(isA<OAuth2AccessTokenEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        verify(tokenRepository, never()).saveRefreshToken(isA<OAuth2RefreshTokenEntity>())

        Assertions.assertNull(token.refreshToken)
    }

    /**
     * Tests the creation of access tokens for clients that are allowed to have refresh tokens.
     */
    @Test
    fun createAccessToken_yesRefresh(): Unit = runBlocking {
        val clientAuth = AuthorizationRequest(
            clientId = clientId,
            isApproved = true,
            scope = hashSetOf(SystemScopeService.OFFLINE_ACCESS),
            requestTime = xxxx,
        )
        whenever(authentication.authorizationRequest) doReturn (clientAuth)
        whenever(client.isAllowRefresh) doReturn (true)
        lateinit var refreshToken: OAuth2RefreshTokenEntity
        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>())) doAnswer { mock ->
            (mock.arguments[0] as OAuth2RefreshTokenEntity).also {
                it.id = it.id ?: 43L
                refreshToken = it
            }
        }

        whenever(tokenRepository.getRefreshTokenById(ArgumentMatchers.anyLong())).doAnswer {
            refreshToken
        }

        val token = service.createAccessToken(authentication, xxx)

        verify(tokenRepository, atMost(1)).getRefreshTokenById(ArgumentMatchers.anyLong())

        // Note: a refactor may be appropriate to only save refresh tokens once to the repository during creation.
        verify(tokenRepository, atLeastOnce()).saveRefreshToken(isA<OAuth2RefreshTokenEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertNotNull(token.refreshToken)
        Assertions.assertEquals(refreshToken, token.refreshToken)
    }

    /**
     * Checks to see that the expiration date of new tokens is being set accurately to within some delta for time skew.
     */
    @Test
    fun createAccessToken_expiration(): Unit = runBlocking {
        val accessTokenValiditySeconds = 3600
        val refreshTokenValiditySeconds = 6000

        whenever(client.accessTokenValiditySeconds) doReturn (accessTokenValiditySeconds)
        whenever(client.refreshTokenValiditySeconds) doReturn (refreshTokenValiditySeconds)

        val start = System.currentTimeMillis()
        val token = service.createAccessToken(authentication, xxx)
        val end = System.currentTimeMillis()

        // Accounting for some delta for time skew on either side.
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA).toInstant()
        val lowerBoundRefreshTokens = Date(start + (refreshTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundRefreshTokens = Date(end + (refreshTokenValiditySeconds * 1000L) + DELTA).toInstant()

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertTrue(token.expirationInstant.isAfter(lowerBoundAccessTokens))
        Assertions.assertTrue(token.expirationInstant.isBefore(upperBoundAccessTokens))

        val rt = token.refreshToken
        Assertions.assertNotNull(rt)
        val exp = rt!!.expirationInstant
        Assertions.assertTrue(exp.isAfter(lowerBoundRefreshTokens))
        Assertions.assertTrue(exp.isBefore(upperBoundRefreshTokens))
    }

    @Test
    fun createAccessToken_checkClient(): Unit = runBlocking {
        val token: OAuth2AccessToken = service.createAccessToken(authentication, xxx)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertEquals(clientId, token.client!!.clientId)
    }

    @Test
    fun createAccessToken_checkScopes(): Unit = runBlocking {
        val token = service.createAccessToken(authentication, xxx)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertEquals(scope, token.scope)
    }

    @Test
    fun createAccessToken_checkAttachedAuthentication(): Unit = runBlocking {
        val authHolder = mock<AuthenticationHolderEntity>()
        whenever(authHolder.authenticatedAuthorizationRequest) doReturn (authentication)

        whenever(authenticationHolderRepository.save(isA<AuthenticationHolderEntity>())) doReturn (authHolder)

        val token = service.createAccessToken(authentication, xxx)

        Assertions.assertEquals(authentication, token.authenticationHolder.authenticatedAuthorizationRequest)
        verify(authenticationHolderRepository).save(isA<AuthenticationHolderEntity>())
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_noRefreshToken(): Unit = runBlocking {
        whenever(tokenRepository.getRefreshTokenByValue(ArgumentMatchers.anyString())) doReturn (null)

        assertThrows<InvalidTokenException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_notAllowRefresh(): Unit = runBlocking {
        whenever(client.isAllowRefresh) doReturn (false)

        assertThrows<InvalidClientException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_clientMismatch(): Unit = runBlocking {
        tokenRequest = AuthorizationRequest(clientId = badClientId, requestTime = xxxx)

        assertThrows<InvalidClientException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_expired(): Unit = runBlocking {
        whenever(refreshToken.isExpired) doReturn (true)

        assertThrows<InvalidTokenException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_verifyAccessToken(): Unit = runBlocking {
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository).clearAccessTokensForRefreshToken(refreshToken)

        Assertions.assertEquals(client, token.client)
        Assertions.assertEquals(refreshToken, token.refreshToken)
        Assertions.assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(any(), eq(storedAuthentication))
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_rotateRefreshToken(): Unit = runBlocking {
        whenever(client.isReuseRefreshToken) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository).clearAccessTokensForRefreshToken(refreshToken)

        Assertions.assertEquals(client, token.client)
        Assertions.assertNotEquals(refreshToken, token.refreshToken)
        Assertions.assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(any(), eq(storedAuthentication))
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(tokenRepository).removeRefreshToken(refreshToken)
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_keepAccessTokens(): Unit = runBlocking {
        whenever(client.isClearAccessTokensOnRefresh) doReturn (false)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(tokenRepository, never()).clearAccessTokensForRefreshToken(refreshToken)

        Assertions.assertEquals(client, token.client)
        Assertions.assertEquals(refreshToken, token.refreshToken)
        Assertions.assertEquals(storedAuthHolder, token.authenticationHolder)

        verify(tokenEnhancer).enhance(any(), eq(storedAuthentication))
        verify(tokenRepository).saveAccessToken(token as OAuth2AccessTokenEntity)
        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())
    }

    @Test
    fun refreshAccessToken_requestingSameScope(): Unit = runBlocking {
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertEquals(storedScope, token.scope)
    }

    @Test
    fun refreshAccessToken_requestingLessScope(): Unit = runBlocking {
        val lessScope: Set<String> = hashSetOf("openid", "profile")

        tokenRequest = tokenRequest.copy(scope = lessScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertEquals(lessScope, token.scope)
    }

    @Test
    fun refreshAccessToken_requestingMoreScope(): Unit = runBlocking {
        val moreScope = storedScope + setOf("address", "phone")

        tokenRequest = tokenRequest.copy(scope = moreScope)

        assertThrows<InvalidScopeException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    /**
     * Tests the case where only some of the valid scope values are being requested along with
     * other extra unauthorized scope values.
     */
    @Test
    fun refreshAccessToken_requestingMixedScope(): Unit = runBlocking {
        val mixedScope: Set<String> =
            setOf("openid", "profile", "address", "phone") // no email or offline_access

        tokenRequest = tokenRequest.copy(scope = mixedScope)

        assertThrows<InvalidScopeException> {
            service.refreshAccessToken(refreshTokenValue, tokenRequest)
        }
    }

    @Test
    fun refreshAccessToken_requestingEmptyScope(): Unit = runBlocking {
        val emptyScope: Set<String> = hashSetOf()

        tokenRequest = tokenRequest.copy(scope = emptyScope)

        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertEquals(storedScope, token.scope)
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
    fun refreshAccessToken_expiration(): Unit = runBlocking {
        val accessTokenValiditySeconds = 3600

        whenever(client.accessTokenValiditySeconds) doReturn (accessTokenValiditySeconds)

        val start = System.currentTimeMillis()
        val token = service.refreshAccessToken(refreshTokenValue, tokenRequest)
        val end = System.currentTimeMillis()

        // Accounting for some delta for time skew on either side.
        val lowerBoundAccessTokens = Date(start + (accessTokenValiditySeconds * 1000L) - DELTA).toInstant()
        val upperBoundAccessTokens = Date(end + (accessTokenValiditySeconds * 1000L) + DELTA).toInstant()

        verify(scopeService, atLeastOnce()).removeReservedScopes(ArgumentMatchers.anySet())

        Assertions.assertTrue(token.expirationInstant.isAfter(lowerBoundAccessTokens))

        Assertions.assertTrue(token.expirationInstant.isBefore(upperBoundAccessTokens))
    }

    @Test
    fun getAllAccessTokensForUser() {
        whenever<Set<OAuth2AccessTokenEntity?>>(tokenRepository.getAccessTokensByUserName(userName)) doReturn(hashSetOf(accessToken))

        val tokens: Set<OAuth2AccessTokenEntity?> = service.getAllAccessTokensForUser(userName)
        Assertions.assertEquals(1, tokens.size)
        Assertions.assertTrue(tokens.contains(accessToken))
    }

    @Test
    fun getAllRefreshTokensForUser() {
        whenever<Set<OAuth2RefreshTokenEntity?>>(tokenRepository.getRefreshTokensByUserName(userName)) doReturn(hashSetOf(refreshToken))

        val tokens: Set<OAuth2RefreshTokenEntity?> = service.getAllRefreshTokensForUser(userName)
        Assertions.assertEquals(1, tokens.size)
        Assertions.assertTrue(tokens.contains(refreshToken))
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
