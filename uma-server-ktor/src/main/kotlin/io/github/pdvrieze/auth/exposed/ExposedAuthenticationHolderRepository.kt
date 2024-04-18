package io.github.pdvrieze.auth.exposed

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.selectAll
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority

class ExposedAuthenticationHolderRepository(database: Database) :
    RepositoryBase(
        database,
        AuthenticationHolders,
        AuthenticationHolderAuthorities,
        AuthenticationHolderResourceIds,
        AuthenticationHolderResponseTypes,
        AuthenticationHolderExtensions,
        AuthenticationHolderScopes,
        AuthenticationHolderRequestParameters,
    ), AuthenticationHolderRepository {

    override val all: List<AuthenticationHolderEntity>
        get() = transaction {
            AuthenticationHolders.selectAll().map {
                it.toAuthenticationHolder()
                TODO()
            }
        }

    override fun getById(id: Long): AuthenticationHolderEntity? {
        TODO("not implemented")
    }

    override val orphanedAuthenticationHolders: List<AuthenticationHolderEntity>
        get() = TODO("not implemented")

    override fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolderEntity> {
        TODO("not implemented")
    }

    override fun save(a: AuthenticationHolderEntity): AuthenticationHolderEntity {
        TODO("not implemented")
    }

    override fun remove(a: AuthenticationHolderEntity) {
        TODO("not implemented")
    }
}

private fun ResultRow.toAuthenticationHolder(): AuthenticationHolderEntity {
    val r = this

    val authHolderId = r[AuthenticationHolders.id].value
    val userAuthId = r[AuthenticationHolders.userAuthId]

    val userAuth = userAuthId?.let { id ->
        SavedUserAuths.selectAll().where { SavedUserAuths.id eq id }
            .singleOrNull()?.toUserAuth()
    }

    val authorities = with(AuthenticationHolderAuthorities) {
        AuthenticationHolderAuthorities.select(authority)
            .where { ownerId eq authHolderId }
            .map { SimpleGrantedAuthority(it[authority]) }
    }

    val resourceIds = with(AuthenticationHolderResourceIds) {
        AuthenticationHolderResourceIds.select(resourceId)
            .where { ownerId eq authHolderId }
            .mapTo(HashSet()) { it[resourceId] }
    }

    val responseTypes = with(AuthenticationHolderResponseTypes) {
        AuthenticationHolderResponseTypes.select(responseType)
            .where { ownerId eq authHolderId }
            .mapTo(HashSet()) { it[responseType] }
    }

    val extensions = with(AuthenticationHolderExtensions) {
        AuthenticationHolderExtensions
            .select(extension, value)
            .where { ownerId eq authHolderId }
            .associate { it[extension] to it[value] }
    }

    val scope = with(AuthenticationHolderScopes) {
        AuthenticationHolderScopes.select(AuthenticationHolderScopes.scope)
            .where { ownerId eq authHolderId }
            .mapTo(HashSet()) { it[AuthenticationHolderScopes.scope] }
    }

    val requestParameters = with (AuthenticationHolderRequestParameters) {
        select(param, value)
        .where { ownerId eq authHolderId }
        .associate { it[param] to it[value] }
    }

    return with(AuthenticationHolders) {
        AuthenticationHolderEntity(
            id = authHolderId,
            userAuth = userAuth,
            authorities = authorities,
            resourceIds = resourceIds,
            isApproved = r[approved] ?: false,
            redirectUri = r[redirectUri],
            responseTypes = responseTypes,
            extensions = extensions,
            clientId = r[clientId],
            scope = scope,
            requestParameters = requestParameters
        )
    }
}

private fun ResultRow.toUserAuth(): SavedUserAuthentication {
    val r = this
    val savedUserId = r[SavedUserAuths.id].value

    val authorities = with(SavedUserAuthAuthorities) {
        selectAll().where { ownerId eq savedUserId }
        .map { SimpleGrantedAuthority(it[authority]) } }

    return with(SavedUserAuths) {
        SavedUserAuthentication(
            id = savedUserId,
            name = r[name],
            authorities = authorities,
            authenticated = r[authenticated],
            sourceClass = r[sourceClass]
        )
    }

}
