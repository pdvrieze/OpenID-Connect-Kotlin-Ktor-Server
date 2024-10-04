package org.mitre.oauth2.repository

import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.resolver.AuthenticationHolderResolver

interface AuthenticationHolderRepository : AuthenticationHolderResolver {
	val all: List<AuthenticationHolderEntity>

    fun remove(a: AuthenticationHolderEntity)

    fun save(a: AuthenticationHolderEntity): AuthenticationHolderEntity

    val orphanedAuthenticationHolders: List<AuthenticationHolderEntity>

    fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolderEntity>
}
