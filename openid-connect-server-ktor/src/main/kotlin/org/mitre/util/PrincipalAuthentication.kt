package org.mitre.util

import com.nimbusds.jwt.JWTParser
import io.ktor.server.auth.*
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority

// TODO this entire code path needs more. It requires looking up users and providing further information.
fun Principal?.toAuth(): PrincipalAuthentication = when (this) {
    is UserIdPrincipal -> UserIdPrincipalAuthentication(this)
    is OAuthAccessTokenResponse.OAuth2 -> OAuth2PrincipalAuthentication(this)
    else -> throw UnsupportedOperationException("Unsupported principal: $this")
}

interface PrincipalAuthentication: Authentication {
    val principal: Principal
}

class UserIdPrincipalAuthentication(
    override val principal: UserIdPrincipal,
    override val authorities: Collection<GrantedAuthority> = emptyList(),
) : PrincipalAuthentication {
    override val name: String get() = principal.name

    override val isAuthenticated: Boolean get() = true
}

class OAuth2PrincipalAuthentication(
    override val principal: OAuthAccessTokenResponse.OAuth2,
): PrincipalAuthentication {

    val jwt = JWTParser.parse(principal.accessToken)
    init {
        TODO("Check jwt is signed with the correct key")
    }


    override val name: String get() = jwt.jwtClaimsSet.subject

    override val authorities: Collection<GrantedAuthority> get() = emptyList()

    override val isAuthenticated: Boolean
        get() = true
}

