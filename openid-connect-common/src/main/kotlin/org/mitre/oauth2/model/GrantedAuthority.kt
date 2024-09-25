package org.mitre.oauth2.model

import kotlinx.serialization.Serializable

@JvmInline
@Serializable
value class GrantedAuthority(val authority: String) {
    companion object {
        val ROLE_EXTERNAL_USER: GrantedAuthority = GrantedAuthority("ROLE_EXTERNAL_USER")
        val ROLE_ADMIN: GrantedAuthority = GrantedAuthority("ROLE_ADMIN")
        val ROLE_CLIENT: GrantedAuthority = GrantedAuthority("ROLE_CLIENT")
        val ROLE_USER: GrantedAuthority = GrantedAuthority("ROLE_USER")
    }
}
