package org.mitre.util

import io.ktor.server.auth.*
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.OAuth2TokenEntityService

// TODO this entire code path needs more. It requires looking up users and providing further information.
fun Any?.toAuth(tokenEntityService: OAuth2TokenEntityService): OldAuthentication = when (this) {
    is UserIdPrincipal -> UserIdPrincipalAuthentication(this, setOf(GrantedAuthority.ROLE_USER))
//    is OAuthAccessTokenResponse.OAuth2 -> tokenEntityService.loadAuthentication(this.accessToken)
    else -> throw UnsupportedOperationException("Unsupported principal: $this")
}

interface PrincipalAuthentication<P>: OldAuthentication {
    val principal: P
}

class UserIdPrincipalAuthentication(
    override val principal: UserIdPrincipal,
    override val authorities: Set<GrantedAuthority> = emptySet(),
) : PrincipalAuthentication<UserIdPrincipal> {
    override val name: String get() = principal.name

    override val isAuthenticated: Boolean get() = true
}

