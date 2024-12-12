package io.github.pdvrieze.auth

import com.nimbusds.jwt.JWT
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

/**
 * An authentication representing a user being authenticated through an openid authentication server.
 */
@Serializable
class OpenIdAuthentication(
    val oidToken: @Serializable(JWTStringConverter::class) JWT,
    override val authTime: ISOInstant = oidToken.jwtClaimsSet.issueTime?.toInstant() ?: Instant.now(),
    val requestedClaims: OpenIdAuthorizationRequest.ClaimsRequest?,
    override val authorities: Set<GrantedAuthority>,
): UserAuthentication, ScopedAuthentication {
    val clientId: String
        get() = oidToken.jwtClaimsSet.getStringClaim("client_id")

    override val userId: String
        get() = oidToken.jwtClaimsSet.subject // Required to be clientId (RFC7523, 3.2B)

    override val scopes: Set<String> = oidToken.jwtClaimsSet.getStringClaim("scope")
        ?.splitToSequence(' ')?.filterNotTo(HashSet()) { it.isBlank() } ?: emptySet()

    override fun hasScope(scope: String): Boolean {
        return scope in this.scopes
    }

}

