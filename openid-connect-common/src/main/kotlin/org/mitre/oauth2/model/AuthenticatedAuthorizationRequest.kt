package org.mitre.oauth2.model

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.DirectUserAuthentication
import io.github.pdvrieze.auth.OpenIdAuthentication
import io.github.pdvrieze.auth.SavedAuthentication
import io.github.pdvrieze.auth.TokenAuthentication
import io.github.pdvrieze.auth.UserAuthentication
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.AuthenticatedAuthorizationRequestSerializer
import org.mitre.oauth2.model.request.AuthorizationRequest
import java.time.Instant

/**
 * Object representing an authorization request that has been associated with a user.
 */
@Serializable(AuthenticatedAuthorizationRequestSerializer::class)
interface AuthenticatedAuthorizationRequest {
    val authorizationRequest: AuthorizationRequest

    val userAuthentication: Authentication?

    @Suppress("DEPRECATION")
    @Deprecated("Authorities would be removed")
    val authorities: Set<GrantedAuthority> get() =
        userAuthentication?.authorities ?: authorizationRequest.authorities

    val isAuthenticated: Boolean
        get() = authorizationRequest.isApproved && userAuthentication.let { it != null && it.authTime.isAfter(Instant.EPOCH) }

    val principalName: String get() = when(val a = userAuthentication) {
        null -> throw IllegalStateException("No authentication")
        is ClientAuthentication -> a.clientId
        is SavedAuthentication -> a.principalName
        is TokenAuthentication -> a.principalName
        is UserAuthentication -> a.userId
    }

    val isClientOnly: Boolean
        get() = userAuthentication == null

    companion object {
        operator fun invoke(
            authorizationRequest: AuthorizationRequest,
            userAuthentication: Authentication?,
        ): AuthenticatedAuthorizationRequest {
            return AuthenticatedAuthorizationRequestImpl(authorizationRequest, userAuthentication)
        }
    }
}

class AuthenticatedAuthorizationRequestImpl(
    override val authorizationRequest: AuthorizationRequest,
    override val userAuthentication: Authentication?,
) : AuthenticatedAuthorizationRequest
