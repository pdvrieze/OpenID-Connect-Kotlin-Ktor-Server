package org.mitre.openid.connect.token

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.pdvrieze.openid.spring.fromSpring
import io.github.pdvrieze.openid.spring.toSpring
import kotlinx.coroutines.runBlocking
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.TokenEnhancer
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.*

@Service
class SpringConnectTokenEnhancer : ConnectTokenEnhancer(), TokenEnhancer {
    @Autowired
    override lateinit var configBean: ConfigurationPropertiesBean

    @Autowired
    override lateinit var jwtService: JWTSigningAndValidationService

    @Autowired
    override lateinit var clientService: ClientDetailsEntityService

    @Autowired
    override lateinit var userInfoService: UserInfoService

    @Autowired
    override lateinit var connectTokenService: OIDCTokenService

    override fun enhance(accessToken: OAuth2AccessToken, authentication: OAuth2Authentication): OAuth2AccessToken {
        val token = accessToken as OAuth2AccessTokenEntity
        val originalAuthRequest = authentication.oAuth2Request

        val clientId = originalAuthRequest.clientId
        val client = checkNotNull(clientService.loadClientByClientId(clientId)) { "Missing client ${clientId}" }

        val builder = JWTClaimsSet.Builder()
            .claim("azp", clientId)
            .issuer(configBean.issuer)
            .issueTime(Date())
            .also {
                if (token.expirationInstant != Instant.MIN) {
                    it.expirationTime(Date.from(token.expirationInstant))
                }
            }
            .subject(authentication.name)
            .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it

        val audience = authentication.oAuth2Request.extensions["aud"] as String?
        if (!audience.isNullOrEmpty()) {
            builder.audience(listOf(audience))
        }

        addCustomAccessTokenClaims(builder, token, authentication)

        val claims = builder.build()

        val signingAlg = jwtService.defaultSigningAlgorithm
        val header = JWSHeader(
            signingAlg, null, null, null, null, null, null, null, null, null,
            jwtService.defaultSignerKeyId,
            true,
            null, null
        )
        val signed = SignedJWT(header, claims)

        jwtService.signJwt(signed)

        token.jwt = signed

        /**
         * Authorization request scope MUST include "openid" in OIDC, but access token request
         * may or may not include the scope parameter. As long as the AuthorizationRequest
         * has the proper scope, we can consider this a valid OpenID Connect request. Otherwise,
         * we consider it to be a vanilla OAuth2 request.
         *
         * Also, there must be a user authentication involved in the request for it to be considered
         * OIDC and not OAuth, so we check for that as well.
         */
        if (originalAuthRequest.scope.contains(SystemScopeService.OPENID_SCOPE)
            && !authentication.isClientOnly
        ) {
            val username = authentication.name
            val userInfo = userInfoService.getByUsernameAndClientId(username, clientId)

            if (userInfo != null) {
                val idToken = runBlocking {
                    connectTokenService.createIdToken(
                        client,
                        originalAuthRequest.fromSpring(), claims.issueTime,
                        userInfo.subject, token.builder()
                    )
                }

                // attach the id token to the parent access token
                token.setIdToken(idToken)
            } else {
                // can't create an id token if we can't find the user
                logger.warn("Request for ID token when no user is present.")
            }
        }

        return token.toSpring()
    }

    /**
     * Hook for subclasses that allows adding custom claims to the JWT that will be used as access token.
     * @param builder the builder holding the current claims
     * @param token the un-enhanced token
     * @param authentication current authentication
     */
    protected fun addCustomAccessTokenClaims(
        builder: JWTClaimsSet.Builder, token: OAuth2AccessTokenEntity?,
        authentication: OAuth2Authentication?
    ) {
    }


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<ConnectTokenEnhancer>()
    }
}
