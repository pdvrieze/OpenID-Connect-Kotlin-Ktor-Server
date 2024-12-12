package io.github.pdvrieze.auth

import com.nimbusds.jwt.SignedJWT
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest

interface UserService {
    /**
     * Create an authentication object that represents a user directly identifying (username/password)
     */
    fun createUserDirectAuthentication(userId: String, vararg factor: AuthFactor): DirectUserAuthentication
    fun createUserOpenIdAuthentication(
        token: SignedJWT,
        requestedClaims: OpenIdAuthorizationRequest.ClaimsRequest? = null
    ): OpenIdAuthentication
    fun createTokenAuthentication(token: SignedJWT): TokenAuthentication
    fun createClientSecretAuthentication(clientId: String): ClientSecretAuthentication
    fun createClientTokenAuthentication(token: SignedJWT): ClientJwtAuthentication

    fun verifyCredentials(userName: String, password: String): Boolean
}
