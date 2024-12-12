package io.github.pdvrieze.auth

import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant

@Serializable
sealed interface Authentication {
    val authTime: ISOInstant
    fun hasScope(scope: String): Boolean
    @Deprecated("Should not be needed")
    val authorities: Set<GrantedAuthority>?
}

sealed interface ScopedAuthentication {
    val scopes: Set<String>
}

