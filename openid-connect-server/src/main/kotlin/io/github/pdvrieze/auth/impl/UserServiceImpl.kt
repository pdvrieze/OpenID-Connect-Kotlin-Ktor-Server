package io.github.pdvrieze.auth.impl

import com.nimbusds.jwt.SignedJWT
import io.github.pdvrieze.auth.AuthFactor
import io.github.pdvrieze.auth.ClientJwtAuthentication
import io.github.pdvrieze.auth.ClientSecretAuthentication
import io.github.pdvrieze.auth.DirectUserAuthentication
import io.github.pdvrieze.auth.OpenIdAuthentication
import io.github.pdvrieze.auth.TokenAuthentication
import io.github.pdvrieze.auth.UserService
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import java.time.Instant

class UserServiceImpl(
    private val authorityProvider: (String) -> Set<GrantedAuthority>,
    private val passwordVerifier: (String, String) -> Boolean
): UserService {
    override fun createUserDirectAuthentication(userId: String, factors: Set<AuthFactor>): DirectUserAuthentication {
        return DirectUserAuthentication(userId, Instant.now(), factors, authorityProvider(userId))
    }

    override fun createUserOpenIdAuthentication(
        token: SignedJWT,
        requestedClaims: OpenIdAuthorizationRequest.ClaimsRequest?
    ): OpenIdAuthentication {
        val auths = authorityProvider(token.jwtClaimsSet.subject).toMutableSet()
        auths.add(GrantedAuthority.ROLE_EXTERNAL_USER)
        return OpenIdAuthentication(token, Instant.now(), requestedClaims, auths)
    }

    override fun createTokenAuthentication(token: SignedJWT): TokenAuthentication {
        TODO("Implement this to check user/client")
//        if (token.jwtClaimsSet.subject)
    }

    override fun createClientSecretAuthentication(clientId: String): ClientSecretAuthentication {
        return ClientSecretAuthentication(clientId, Instant.now())
    }

    override fun createClientTokenAuthentication(token: SignedJWT): ClientJwtAuthentication {
        return ClientJwtAuthentication(token, Instant.now())
    }

    override fun verifyCredentials(userName: String, password: String): Boolean {
        return passwordVerifier(userName, password)
    }
}
