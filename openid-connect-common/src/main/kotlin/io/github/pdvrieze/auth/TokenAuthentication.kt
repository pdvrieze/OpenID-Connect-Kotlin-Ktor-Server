package io.github.pdvrieze.auth

import com.nimbusds.jwt.JWT
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.oauth2.model.request.AuthorizationRequest

/** An authentication representing an access token that may not be directly controlled by a user */
@Serializable
abstract class TokenAuthentication: Authentication, ScopedAuthentication, AuthenticatedAuthorizationRequest, AuthorizationRequest {
    val token: @Serializable(JWTStringConverter::class) JWT
    override val clientId: String get(): String = token.jwtClaimsSet.getStringClaim("client_id")

    constructor(token: JWT) { this.token = token }

    override val principalName: String
        get() = token.jwtClaimsSet.subject

    override val authorizationRequest: AuthorizationRequest
        get() = this
    override val subjectAuth: SavedAuthentication
        get() = SavedAuthentication.from(this)
    override val authorities: Set<GrantedAuthority>
        get() = when { // Check this
            token.jwtClaimsSet.subject == clientId -> setOf(GrantedAuthority.ROLE_CLIENT)
            else -> setOf(GrantedAuthority.ROLE_USER)
        }
    override val scopes get() = scope

    override val scope: Set<String>
        get() = token.jwtClaimsSet.getStringClaim("scope").orEmpty().split(' ').toCollection(HashSet())
}
