package org.mitre.util

import com.nimbusds.jwt.JWTParser
import io.ktor.server.auth.*
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RefreshToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.ClientDetailsEntityService
import java.time.Instant

// TODO this entire code path needs more. It requires looking up users and providing further information.
fun Principal?.toAuth(clientDetailsEntityService: ClientDetailsEntityService): Authentication = when (this) {
    is UserIdPrincipal -> UserIdPrincipalAuthentication(this)
    is OAuthAccessTokenResponse.OAuth2 -> OAuth2PrincipalJwtAuthentication(this, clientDetailsEntityService)
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

class OAuth2PrincipalJwtAuthentication(
    override val principal: OAuthAccessTokenResponse.OAuth2,
    clientDetailsEntityService: ClientDetailsEntityService,
): PrincipalAuthentication, OAuth2AccessToken {
    override val value: String get() = principal.accessToken

    override val jwt = JWTParser.parse(principal.accessToken)

    override val name: String get() = jwt.jwtClaimsSet.subject

    override val refreshToken: OAuth2RefreshToken? get() = null

    override val scope: Set<String> = jwt.jwtClaimsSet.getStringClaim("scope")?.let {
        it.splitToSequence(' ').filterNotTo(HashSet()) { it.isBlank() }
    } ?: emptySet()

    // TODO get this initialised properly with a service that can extract authorities (if by the right issuer)
    override val authorities: Collection<GrantedAuthority> get() = emptySet()

    override val tokenType: String get() = OAuth2AccessToken.BEARER_TYPE

    override val expirationInstant: Instant get() = jwt.jwtClaimsSet.expirationTime.toInstant()

    override val isExpired: Boolean
        get() = ! Instant.now().isBefore(expirationInstant)

    override val client: OAuthClientDetails? = jwt.jwtClaimsSet.getStringClaim("client_id")?.let {
        clientDetailsEntityService.loadClientByClientId(it)
    }

    override val authenticationHolder: AuthenticationHolderEntity
        get() = AuthenticationHolderEntity(clientId = client?.clientId)

    override fun builder(): OAuth2AccessToken.Builder {
        TODO("not implemented")
    }

    // TODO This needs validation
    override val isAuthenticated: Boolean
        get() = true
}

