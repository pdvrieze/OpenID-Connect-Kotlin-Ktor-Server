package org.mitre.openid.connect.ktor.token

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.token.ConnectTokenEnhancer
import org.mitre.openid.connect.token.ConnectTokenEnhancerImpl
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.whenever
import java.text.ParseException
import java.time.Instant

@ExtendWith(MockitoExtension::class)
class TestKtorConnectTokenEnhancer {
    private val configBean = ConfigurationPropertiesBean()

    @Mock
    private lateinit var jwtService: JWTSigningAndValidationService

    @Mock
    private lateinit var clientService: ClientDetailsEntityService

    @Mock
    private lateinit var userInfoService: UserInfoService

    @Mock
    private lateinit var connectTokenService: OIDCTokenService

    @Mock
    private lateinit var authentication: AuthenticatedAuthorizationRequest

    private val request: AuthorizationRequest = PlainAuthorizationRequest.Builder(clientId = CLIENT_ID).also { b ->
        b.requestTime = Instant.now()
    }.build()

    private lateinit var enhancer: ConnectTokenEnhancer

    @BeforeEach
    fun prepare() {
        configBean.issuer = "https://auth.example.org/"

        // recreate it every time (to replicate spring behaviour)
        enhancer = ConnectTokenEnhancerImpl(
            clientService = clientService,
            configBean = configBean,
            jwtService = jwtService,
            userInfoService = userInfoService,
            connectTokenServiceProvider = { connectTokenService }
        )

        val client = ClientDetailsEntity.Builder(
            clientId = CLIENT_ID
        ).build()
        whenever(clientService.loadClientByClientId(ArgumentMatchers.anyString())).thenReturn(client)
        whenever(authentication.authorizationRequest).thenReturn(request)
        whenever(jwtService.defaultSigningAlgorithm).thenReturn(JWSAlgorithm.RS256)
        whenever(jwtService.defaultSignerKeyId).thenReturn(KEY_ID)
    }

    @Test
    @Throws(ParseException::class)
    fun invokesCustomClaimsHook(): Unit = runBlocking {
        enhancer = object : ConnectTokenEnhancerImpl(
            clientService, configBean, jwtService, userInfoService, { connectTokenService }
        ) {
            override fun addCustomAccessTokenClaims(
                builder: JWTClaimsSet.Builder,
                token: OAuth2AccessToken.Builder,
                authentication: AuthenticatedAuthorizationRequest?
            ) {
                builder.claim("test", "foo")
            }
        }

        val tokenBuilder = OAuth2AccessTokenEntity.Builder()

        enhancer.enhance(tokenBuilder, authentication)
        Assertions.assertEquals("foo", tokenBuilder.jwt!!.jwtClaimsSet.getClaim("test"))
    }

    companion object {
        private const val CLIENT_ID = "client"
        private const val KEY_ID = "key"
    }
}
