package org.mitre.util

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

class UserIdPrincipalAuthentication(override val principal: UserIdPrincipal) : PrincipalAuthentication {
    override val name: String get() = principal.name

    override val isAuthenticated: Boolean get() = true

    override val authorities: Collection<GrantedAuthority> get() = emptyList()
}

class OAuth2PrincipalAuthentication(override val principal: OAuthAccessTokenResponse): PrincipalAuthentication {

    override val name: String get() = throw UnsupportedOperationException("No name")

    override val authorities: Collection<GrantedAuthority> get() = emptyList()

    override val isAuthenticated: Boolean
        get() = true
}
