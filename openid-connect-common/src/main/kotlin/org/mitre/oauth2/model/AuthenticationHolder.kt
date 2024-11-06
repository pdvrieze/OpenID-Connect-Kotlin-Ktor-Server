package org.mitre.oauth2.model

import org.mitre.openid.connect.model.convert.ISOInstant

interface AuthenticationHolder {
    fun copy(id: Long?): AuthenticationHolder

    val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
    val id: Long?
    val userAuth: SavedUserAuthentication?
    val authorities: Collection<GrantedAuthority>?
    val resourceIds: Set<String>?
    val isApproved: Boolean
    val redirectUri: String?
    val responseTypes: Set<String>?
    val extensions: Map<String, String>?
    val clientId: String?
    val scope: Set<String>?
    val requestParameters: Map<String, String>?
    val requestTime: ISOInstant?

    object DUMMY: AuthenticationHolder {
        override val id: Nothing? get() = null
        override val userAuth: Nothing? get() = null
        override val authorities: Nothing? get() = null
        override val resourceIds: Nothing? get() = null
        override val isApproved: Boolean get() = false
        override val redirectUri: Nothing? get() = null
        override val responseTypes: Nothing? get() = null
        override val extensions: Nothing? get() = null
        override val clientId: Nothing? get() = null
        override val scope: Nothing? get() = null
        override val requestParameters: Nothing? get() = null
        override val requestTime: Nothing? get() = null
        override fun copy(id: Long?): DUMMY = DUMMY
        override val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
            get() = throw UnsupportedOperationException()
    }
}
