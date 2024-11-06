package org.mitre.oauth2.repository

import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolder
import org.mitre.oauth2.resolver.AuthenticationHolderResolver

interface AuthenticationHolderRepository : AuthenticationHolderResolver {
	val all: List<AuthenticationHolder>

    fun remove(a: AuthenticationHolder)

    fun save(a: AuthenticationHolder): AuthenticationHolder

    val orphanedAuthenticationHolders: List<AuthenticationHolder>

    fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolder>
}
