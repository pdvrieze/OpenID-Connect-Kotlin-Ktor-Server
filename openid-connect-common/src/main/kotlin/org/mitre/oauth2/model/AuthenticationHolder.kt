package org.mitre.oauth2.model

import org.mitre.oauth2.model.request.AuthorizationRequest

/**
 * Class that holds an authenticated authorization request as stored in the database (it has an ID).
 */
interface AuthenticationHolder {
    fun copy(id: Long?): AuthenticationHolder

    val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
        get() = AuthenticatedAuthorizationRequest(authorizationRequest, userAuth)

    val id: Long?
    val userAuth: SavedUserAuthentication?
    val authorizationRequest: AuthorizationRequest

    object DUMMY: AuthenticationHolder {
        override val id: Nothing? get() = null
        override val userAuth: Nothing? get() = null
        override fun copy(id: Long?): DUMMY = DUMMY
        override val authorizationRequest: AuthorizationRequest
            get() = throw UnsupportedOperationException()
    }
}
