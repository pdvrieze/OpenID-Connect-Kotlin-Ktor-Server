package io.github.pdvrieze.auth

import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant

@Serializable
data class ClientSecretAuthentication(
    override val clientId: String,
    override val authTime: ISOInstant,
    override val scopes: Set<String> = emptySet(),
): ClientAuthentication {
    override fun hasScope(scope: String): Boolean {
        return scope in scopes
    }

    override val authorities: Set<GrantedAuthority> get() = setOf(GrantedAuthority.ROLE_CLIENT)
}
