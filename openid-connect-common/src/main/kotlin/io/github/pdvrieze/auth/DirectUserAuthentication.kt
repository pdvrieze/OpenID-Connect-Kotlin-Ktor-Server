package io.github.pdvrieze.auth

import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant

/** Authentication representing a user directly authenticating their own identity. */
@Serializable
data class DirectUserAuthentication(
    override val userId: String,
    override val authTime: ISOInstant,
    val authMethods: Set<AuthFactor>,
    override val authorities: Set<GrantedAuthority> = setOf(GrantedAuthority.ROLE_USER),
) : UserAuthentication {
    override fun hasScope(scope: String): Boolean {
        return false
    }
}
