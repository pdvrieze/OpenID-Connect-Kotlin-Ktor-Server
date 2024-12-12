package org.mitre.oauth2.model

@Deprecated("")
interface OldAuthentication {
    val authorities: Set<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

