package org.mitre.oauth2.model

import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.AuthenticatedAuthorizationRequestSerializer
import org.mitre.oauth2.model.request.AuthorizationRequest

/**
 * Object representing an authorization request that has been associated with a user.
 */
@Serializable(AuthenticatedAuthorizationRequestSerializer::class)
interface AuthenticatedAuthorizationRequest {
    val authorizationRequest: AuthorizationRequest

    val userAuthentication: SavedUserAuthentication?

    val authorities: Set<GrantedAuthority> get() =
        userAuthentication?.authorities ?: authorizationRequest.authorities

    val isAuthenticated: Boolean
        get() = authorizationRequest.isApproved && (userAuthentication?.isAuthenticated == true)

    val name: String
        get() = userAuthentication?.name ?: authorizationRequest.clientId

    val isClientOnly: Boolean
        get() = userAuthentication == null

    companion object {
        operator fun invoke(
            authorizationRequest: AuthorizationRequest,
            userAuthentication: SavedUserAuthentication?,
        ): AuthenticatedAuthorizationRequest {
            return AuthenticatedAuthorizationRequestImpl(authorizationRequest, userAuthentication)
        }
    }
}

class AuthenticatedAuthorizationRequestImpl(
    override val authorizationRequest: AuthorizationRequest,
    override val userAuthentication: SavedUserAuthentication?,
) : AuthenticatedAuthorizationRequest
