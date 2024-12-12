package io.github.pdvrieze.auth

import com.nimbusds.jwt.JWT
import kotlinx.serialization.Serializable
import org.mitre.oauth2.introspectingfilter.IntrospectionResponse
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

@Serializable
sealed interface UserAuthentication : Authentication {

    val userId: String
    override val authorities: Set<GrantedAuthority>

    @Deprecated("No longer used", ReplaceWith("userId"))
    val name get() = userId
}

@Serializable
class UserJwtAuthentication(
    val token: @Serializable(JWTStringConverter::class) JWT,
    override val authTime: ISOInstant = token.jwtClaimsSet.issueTime?.toInstant() ?: Instant.now(),
    override val authorities: Set<GrantedAuthority>,
    val scopes: Set<String> = token.jwtClaimsSet.getStringClaim("scope")?.splitToSequence(' ')?.filterNot { it.isBlank() }?.toSet() ?: emptySet(),
): UserAuthentication {
    override val userId: String get() = token.jwtClaimsSet.subject

    override fun hasScope(scope: String): Boolean {
        return scope in scopes
    }
}

@Serializable
class UserIntrospectionAuthentication private constructor(
    val opaqueToken: String,
    override val userId: String,
    override val authTime: ISOInstant,
    override val authorities: Set<GrantedAuthority>,
    val scopes: Set<String>,
): UserAuthentication {

    constructor(opaqueToken: String, introspectionResponse: IntrospectionResponse, authorities: Set<GrantedAuthority>) : this(
        opaqueToken = opaqueToken,
        userId = requireNotNull(introspectionResponse.subject ?: introspectionResponse.username),
        authTime = introspectionResponse.issuedAt ?: Instant.ofEpochSecond(1L),
        authorities = authorities,
        scopes = introspectionResponse.scopes
    )

    override fun hasScope(scope: String): Boolean {
        return scope in scopes
    }
}
