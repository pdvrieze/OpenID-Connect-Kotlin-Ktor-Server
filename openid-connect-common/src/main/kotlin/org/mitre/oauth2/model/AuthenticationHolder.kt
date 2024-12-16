package org.mitre.oauth2.model

import io.github.pdvrieze.auth.SavedAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest

/**
 * Class that holds an authenticated authorization request as stored in the database (it has an ID).
 */
interface AuthenticationHolder: AuthenticatedAuthorizationRequest {
    fun copy(id: Long?): AuthenticationHolder

    val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
        get() = this

    val id: Long?
    override val subjectAuth: SavedAuthentication?
    override val authorizationRequest: AuthorizationRequest

    object DUMMY: AuthenticationHolder {
        override val id: Nothing? get() = null
        override val subjectAuth: Nothing? get() = null
        override val authorizationRequest: AuthorizationRequest
            get() = throw UnsupportedOperationException()
        override fun copy(id: Long?): DUMMY = DUMMY
    }
}
