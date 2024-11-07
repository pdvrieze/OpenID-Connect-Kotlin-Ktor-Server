package org.mitre.oauth2.model

interface Authentication {
    val authorities: Set<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

