package org.mitre.oauth2.model

interface Authentication {
    val authorities: Collection<GrantedAuthority>
    val isAuthenticated: Boolean
    val name: String
}

