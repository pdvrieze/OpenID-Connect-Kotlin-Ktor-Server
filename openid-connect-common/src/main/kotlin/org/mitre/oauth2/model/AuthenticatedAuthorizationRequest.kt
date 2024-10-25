package org.mitre.oauth2.model

import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.AuthenticatedAuthorizationRequestSerializer
import org.mitre.oauth2.model.convert.AuthorizationRequest

/**
 * Object representing an authorization request that has been associated with a user.
 */
@Serializable(AuthenticatedAuthorizationRequestSerializer::class)
class AuthenticatedAuthorizationRequest(
    val authorizationRequest: AuthorizationRequest,
    val userAuthentication: SavedUserAuthentication?
) {

    val authorities: Collection<GrantedAuthority> =
        userAuthentication?.authorities ?: authorizationRequest.authorities

    val isAuthenticated: Boolean
        get() = authorizationRequest.isApproved && (userAuthentication == null || userAuthentication.isAuthenticated)

    val name: String
        get() = userAuthentication?.name ?: authorizationRequest.clientId

    val isClientOnly: Boolean
        get() = userAuthentication == null
}

