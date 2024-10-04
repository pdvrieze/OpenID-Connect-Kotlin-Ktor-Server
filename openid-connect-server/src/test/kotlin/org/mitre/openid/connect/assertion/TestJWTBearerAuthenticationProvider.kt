package org.mitre.openid.connect.assertion

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.util.assertIs
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.isA
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import java.util.*
import java.util.concurrent.TimeUnit

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestJWTBearerAuthenticationProvider {
    @Mock
    private lateinit var validators: ClientKeyCacheService

    @Mock
    private lateinit var clientService: ClientDetailsEntityService

    @Mock
    private lateinit var config: ConfigurationPropertiesBean

    @InjectMocks
    private lateinit var jwtBearerAuthenticationProvider: JWTBearerAuthenticationProvider

    @Mock
    private lateinit var token: JWTBearerAssertionAuthenticationToken

    @Mock
    private lateinit var client: ClientDetailsEntity

    @Mock
    private lateinit var validator: JWTSigningAndValidationService

    @BeforeEach
    fun setup() {
        whenever(clientService.loadClientByClientId(CLIENT_ID)).thenReturn(client)

        whenever(token.name).thenReturn(CLIENT_ID)

        whenever(client.clientId).thenReturn(CLIENT_ID)
        whenever(client.tokenEndpointAuthMethod).thenReturn(AuthMethod.NONE)
        whenever(client.authorities).thenReturn(setOf(authority1, authority2, authority3))

        whenever(validators.getValidator(client, JWSAlgorithm.RS256)).thenReturn(validator)
        whenever(validator.validateSignature(isA<SignedJWT>())).thenReturn(true)

        whenever(config.issuer).thenReturn("http://issuer.com/")
    }

    @Test
    fun should_not_support_UsernamePasswordAuthenticationToken() {
        assertFalse(jwtBearerAuthenticationProvider.supports(UsernamePasswordAuthenticationToken::class.java))
    }

    @Test
    fun should_support_JWTBearerAssertionAuthenticationToken() {
        assertTrue(jwtBearerAuthenticationProvider.supports(JWTBearerAssertionAuthenticationToken::class.java))
    }

    @Test
    fun should_throw_UsernameNotFoundException_when_clientService_throws_InvalidClientException() {
        whenever(clientService.loadClientByClientId(CLIENT_ID))
            .thenThrow(InvalidClientException("invalid client"))

        val thrown = authenticateAndReturnThrownException()

        assertIs<UsernameNotFoundException>(thrown)
        assertEquals("Could not find client: $CLIENT_ID", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_PlainJWT() {
        mockPlainJWTAuthAttempt()

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Unsupported JWT type: " + PlainJWT::class.java.name, thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_EncryptedJWT() {
        mockEncryptedJWTAuthAttempt()

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Unsupported JWT type: " + EncryptedJWT::class.java.name, thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_signing_algorithms_do_not_match() {
        whenever(client.tokenEndpointAuthSigningAlg).thenReturn(JWSAlgorithm.RS256)
        val signedJWT = createSignedJWT(JWSAlgorithm.ES384)
        whenever(token.jwt).thenReturn(signedJWT)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Client's registered token endpoint signing algorithm (RS256) does not match token's actual algorithm (ES384)", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_unsupported_authentication_method_for_SignedJWT() {
        val unsupportedAuthMethods =
            Arrays.asList(null, AuthMethod.NONE, AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST)

        for (unsupportedAuthMethod in unsupportedAuthMethods) {
            val signedJWT = createSignedJWT()
            whenever(token.jwt).thenReturn(signedJWT)
            whenever(client.tokenEndpointAuthMethod).thenReturn(unsupportedAuthMethod)

            val thrown = authenticateAndReturnThrownException()

            assertIs<AuthenticationServiceException>(thrown)
            assertEquals("Client does not support this authentication method.", thrown.message)
        }
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_invalid_algorithm_for_PRIVATE_KEY_auth_method() {
        val invalidAlgorithms = Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512)

        for (algorithm in invalidAlgorithms) {
            val signedJWT = createSignedJWT(algorithm)
            whenever(token.jwt).thenReturn(signedJWT)
            whenever(client.tokenEndpointAuthMethod).thenReturn(AuthMethod.PRIVATE_KEY)
            whenever(client.tokenEndpointAuthSigningAlg).thenReturn(algorithm)

            val thrown = authenticateAndReturnThrownException()

            assertIs<AuthenticationServiceException>(thrown)
            assertEquals(true, thrown.message?.startsWith("Unable to create signature validator for method"))
        }
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_invalid_algorithm_for_SECRET_JWT_auth_method() {
        val invalidAlgorithms = Arrays.asList(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512
        )

        for (algorithm in invalidAlgorithms) {
            val signedJWT = createSignedJWT(algorithm)
            whenever(token.jwt).thenReturn(signedJWT)
            whenever(client.tokenEndpointAuthMethod).thenReturn(AuthMethod.SECRET_JWT)
            whenever(client.tokenEndpointAuthSigningAlg).thenReturn(algorithm)

            val thrown = authenticateAndReturnThrownException()

            assertIs<AuthenticationServiceException>(thrown)
            assertEquals(true, thrown.message?.startsWith("Unable to create signature validator for method"))
        }
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_in_heart_mode_and_auth_method_is_not_PRIVATE_KEY() {
        val signedJWT = createSignedJWT(JWSAlgorithm.HS256)
        whenever(token.jwt).thenReturn(signedJWT)
        whenever(client.tokenEndpointAuthSigningAlg).thenReturn(JWSAlgorithm.HS256)
        whenever(config.isHeartMode).thenReturn(true)
        whenever(client.tokenEndpointAuthMethod).thenReturn(AuthMethod.SECRET_JWT)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("[HEART mode] Invalid authentication method", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_null_validator() {
        mockSignedJWTAuthAttempt()
        whenever(validators.getValidator(isA<ClientDetailsEntity>(), isA<JWSAlgorithm>()))
            .thenReturn(null)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Unable to create signature validator for client"))
    }

    @Test
    fun should_throw_AuthenticationServiceException_for_SignedJWT_when_invalid_signature() {
        val signedJWT = mockSignedJWTAuthAttempt()
        whenever(validator.validateSignature(signedJWT)).thenReturn(false)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Signature did not validate for presented JWT authentication.", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_null_issuer() {
        val jwtClaimsSet = JWTClaimsSet.Builder().issuer(null).build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Assertion Token Issuer is null", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_not_matching_issuer() {
        val jwtClaimsSet = JWTClaimsSet.Builder().issuer("not matching").build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Issuers do not match"))
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_null_expiration_time() {
        val jwtClaimsSet = JWTClaimsSet.Builder().issuer(CLIENT_ID).expirationTime(null).build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals("Assertion Token does not have required expiration claim", thrown.message)
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_expired_jwt() {
        val expiredDate = Date(System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(500))
        val jwtClaimsSet = JWTClaimsSet.Builder().issuer(CLIENT_ID).expirationTime(expiredDate).build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Assertion Token is expired"))
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_jwt_valid_in_future() {
        val futureDate = Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(500))
        val jwtClaimsSet =
            JWTClaimsSet.Builder().issuer(CLIENT_ID).expirationTime(futureDate).notBeforeTime(futureDate).build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Assertion Token not valid until"))
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_jwt_issued_in_future() {
        val futureDate = Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(500))
        val jwtClaimsSet =
            JWTClaimsSet.Builder().issuer(CLIENT_ID).expirationTime(futureDate).issueTime(futureDate).build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Assertion Token was issued in the future"))
    }

    @Test
    fun should_throw_AuthenticationServiceException_when_unmatching_audience() {
        val jwtClaimsSet = JWTClaimsSet.Builder().issuer(CLIENT_ID).expirationTime(Date()).audience("invalid").build()
        mockSignedJWTAuthAttempt(jwtClaimsSet)

        val thrown = authenticateAndReturnThrownException()

        assertIs<AuthenticationServiceException>(thrown)
        assertEquals(true, thrown.message?.startsWith("Audience does not match"))
    }

    @Test
    fun should_return_valid_token_when_audience_contains_token_endpoint() {
        val jwtClaimsSet = JWTClaimsSet.Builder()
            .issuer(CLIENT_ID)
            .subject(SUBJECT)
            .expirationTime(Date())
            .audience(listOf("http://issuer.com/token", "invalid"))
            .build()
        val jwt: JWT = mockSignedJWTAuthAttempt(jwtClaimsSet)

        val authentication = jwtBearerAuthenticationProvider.authenticate(token)

        assertIs<JWTBearerAssertionAuthenticationToken>(authentication)

        val token = authentication as JWTBearerAssertionAuthenticationToken
        assertEquals(SUBJECT, token.name)
        assertEquals(jwt, token.jwt)
        assertTrue(token.authorities.map { LocalGrantedAuthority(it.authority) }.containsAll(listOf(authority1, authority2, authority3)))
        assertEquals(4, token.authorities.size)
    }

    @Test
    fun should_return_valid_token_when_issuer_does_not_end_with_slash_and_audience_contains_token_endpoint() {
        val jwtClaimsSet = JWTClaimsSet.Builder()
            .issuer(CLIENT_ID)
            .subject(SUBJECT)
            .expirationTime(Date())
            .audience(listOf("http://issuer.com/token"))
            .build()
        val jwt: JWT = mockSignedJWTAuthAttempt(jwtClaimsSet)
        whenever(config.issuer).thenReturn("http://issuer.com/")

        val authentication = jwtBearerAuthenticationProvider.authenticate(token)

        assertIs<JWTBearerAssertionAuthenticationToken>(authentication)

        val token = authentication as JWTBearerAssertionAuthenticationToken
        assertEquals(SUBJECT, token.name)
        assertEquals(jwt, token.jwt)
        assertTrue(token.authorities.map { LocalGrantedAuthority(it.authority) }.containsAll(listOf(authority1, authority2, authority3)))
        assertEquals(4, token.authorities.size)
    }

    private fun mockPlainJWTAuthAttempt() {
        val plainJWT = PlainJWT(createJwtClaimsSet())
        whenever(token.jwt).thenReturn(plainJWT)
    }

    private fun mockEncryptedJWTAuthAttempt() {
        val jweHeader = JWEHeader.Builder(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256GCM).build()
        val encryptedJWT = EncryptedJWT(jweHeader, createJwtClaimsSet())
        whenever(token.jwt).thenReturn(encryptedJWT)
    }

    private fun mockSignedJWTAuthAttempt(jwtClaimsSet: JWTClaimsSet = createJwtClaimsSet()): SignedJWT {
        val signedJWT = createSignedJWT(JWSAlgorithm.RS256, jwtClaimsSet)
        whenever(token.jwt).thenReturn(signedJWT)
        whenever(client.tokenEndpointAuthMethod).thenReturn(AuthMethod.PRIVATE_KEY)
        whenever(client.tokenEndpointAuthSigningAlg).thenReturn(JWSAlgorithm.RS256)
        return signedJWT
    }

    private fun authenticateAndReturnThrownException(): Throwable {
        try {
            jwtBearerAuthenticationProvider.authenticate(token)
        } catch (throwable: Throwable) {
            return throwable
        }
        throw AssertionError("No exception thrown when expected")
    }

    private fun createSignedJWT(jwsAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): SignedJWT {
        val jwsHeader = JWSHeader.Builder(jwsAlgorithm).build()
        val claims = createJwtClaimsSet()

        return SignedJWT(jwsHeader, claims)
    }

    private fun createSignedJWT(jwsAlgorithm: JWSAlgorithm, jwtClaimsSet: JWTClaimsSet): SignedJWT {
        val jwsHeader = JWSHeader.Builder(jwsAlgorithm).build()

        return SignedJWT(jwsHeader, jwtClaimsSet)
    }

    private fun createJwtClaimsSet(): JWTClaimsSet {
        return JWTClaimsSet.Builder()
            .issuer(CLIENT_ID)
            .expirationTime(Date())
            .audience("http://issuer.com/")
            .build()
    }

    companion object {
        private const val CLIENT_ID = "client"
        private const val SUBJECT = "subject"
        private val authority1: GrantedAuthority = LocalGrantedAuthority("1")
        private val authority2: GrantedAuthority = LocalGrantedAuthority("2")
        private val authority3: GrantedAuthority = LocalGrantedAuthority("3")
    }
}
