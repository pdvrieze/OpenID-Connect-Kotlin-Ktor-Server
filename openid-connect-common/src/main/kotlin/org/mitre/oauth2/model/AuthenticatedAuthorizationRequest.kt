package org.mitre.oauth2.model

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.SavedAuthentication
import io.github.pdvrieze.auth.TokenAuthentication
import io.github.pdvrieze.auth.UserAuthentication
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.AuthenticatedAuthorizationRequestSerializer
import org.mitre.oauth2.model.request.AuthorizationRequest
import java.time.Instant

/**
 * Object representing an authorization request that has been associated with a subject (user/client).
 */
@Serializable(AuthenticatedAuthorizationRequestSerializer::class)
interface AuthenticatedAuthorizationRequest {
    val authorizationRequest: AuthorizationRequest

    val subjectAuth: Authentication?

    @Suppress("DEPRECATION")
    @Deprecated("Authorities would be removed")
    val authorities: Set<GrantedAuthority> get() =
        subjectAuth?.authorities ?: authorizationRequest.authorities

    val isAuthenticated: Boolean
        get() = authorizationRequest.isApproved && subjectAuth.let { it != null && it.authTime.isAfter(Instant.EPOCH) }

    val principalName: String get() = when(val a = subjectAuth) {
        null -> throw IllegalStateException("No authentication: not authenticated")
        is ClientAuthentication -> a.clientId
        is SavedAuthentication -> a.principalName
        is TokenAuthentication -> a.principalName
        is UserAuthentication -> a.userId
    }

    val isClientOnly: Boolean
        get() = subjectAuth == null

    companion object {
        operator fun invoke(
            authorizationRequest: AuthorizationRequest,
            subjectAuth: Authentication?,
        ): AuthenticatedAuthorizationRequest {
            return AuthenticatedAuthorizationRequestImpl(authorizationRequest, subjectAuth)
        }
    }
}

class AuthenticatedAuthorizationRequestImpl(
    override val authorizationRequest: AuthorizationRequest,
    override val subjectAuth: Authentication?,
) : AuthenticatedAuthorizationRequest
