package org.mitre.openid.connect.service.impl

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.lang.invoke.MethodHandles
import java.text.ParseException
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
class TestKtorOIDCTokenService {
    private val tokenService: OAuth2TokenEntityService = mock()
    private val symmetricCacheService: SymmetricKeyJWTValidatorCacheService = mock()
    private val encrypters: ClientKeyCacheService = mock()
    private val authenticationHolderRepository: AuthenticationHolderRepository = mock()

    private val configBean = ConfigurationPropertiesBean("http://localhost")
    private val client = ClientDetailsEntity()
    private val accessToken = OAuth2AccessTokenEntity(
        authenticationHolder = AuthenticationHolderEntity(),
        expirationInstant = Instant.now().plusSeconds(120),
        jwt = PlainJWT(JWTClaimsSet.Builder().build()),
    )
    private val request: OAuth2Request = OAuth2Request(clientId = CLIENT_ID)

    @Mock
    private lateinit var jwtService: JWTSigningAndValidationService

    @BeforeEach
    fun prepare() {
        configBean.issuer = "https://auth.example.org/"

        client.setClientId(CLIENT_ID)
        whenever(jwtService.defaultSigningAlgorithm).thenReturn(JWSAlgorithm.RS256)
        whenever(jwtService.defaultSignerKeyId).thenReturn(KEY_ID)
    }

    @Test
    @Throws(ParseException::class)
    fun invokesCustomClaimsHook() {
        val m = KtorOIDCTokenService::class.java.declaredMethods.first { it.name == "addCustomIdTokenClaims" }
        m.isAccessible = true
        val mh = MethodHandles.lookup()
            .unreflect(m)
        val s: KtorOIDCTokenService =
            spy<KtorOIDCTokenService>(KtorOIDCTokenService(jwtService, authenticationHolderRepository, configBean, encrypters, symmetricCacheService, tokenService)) {
                mh.invoke(doAnswer { invocation ->
                    val idClaims = invocation.arguments[0] as JWTClaimsSet.Builder
                    idClaims.claim("test", "foo")
                }.whenever(mock), isA(), isA(), any(), any(), any())
            }

        val issueTime = Date()
        val token = s.createIdToken(client, request, issueTime, "sub", accessToken.builder())!!

        // TODO: Check this is tested in other tests
        assertEquals("foo", token.jwtClaimsSet.getClaim("test"))
        assertEquals("sub", token.jwtClaimsSet.subject)
        assertEquals(issueTime, token.jwtClaimsSet.issueTime)
    }


    companion object {
        private const val CLIENT_ID = "client"
        private const val KEY_ID = "key"
    }
}
