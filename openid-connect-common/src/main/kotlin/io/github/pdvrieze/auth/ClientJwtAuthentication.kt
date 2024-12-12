package io.github.pdvrieze.auth

import com.nimbusds.jwt.JWT
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

/**
 * A client authenticated using an access token from the "client_credentials".
 */
@Serializable
class ClientJwtAuthentication(
    val token: @Serializable(JWTStringConverter::class) JWT,
    override val authTime: ISOInstant = token.jwtClaimsSet.issueTime?.toInstant() ?: Instant.now(),
    override val scopes: Set<String> = token.jwtClaimsSet.getStringClaim("scope")?.splitToSequence(' ')?.filterNot { it.isBlank() }?.toSet() ?: emptySet(),
) : ClientAuthentication {
    override val clientId: String
        get() = token.jwtClaimsSet.subject // Required to be clientId (RFC7523, 3.2B)

    override fun hasScope(scope: String): Boolean {
        return scope in scopes
    }

    override val authorities: Set<GrantedAuthority> get() = setOf(GrantedAuthority.ROLE_CLIENT)
}
