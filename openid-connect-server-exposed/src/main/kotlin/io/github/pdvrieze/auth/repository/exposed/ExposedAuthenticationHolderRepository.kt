package io.github.pdvrieze.auth.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.data.DefaultPageCriteria
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.repository.AuthenticationHolderRepository

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
            }
        }

    override fun getById(id: Long): AuthenticationHolderEntity? = transaction {
        AuthenticationHolders.selectAll().where { AuthenticationHolders.id eq id }.map {
            it.toAuthenticationHolder()
        }.singleOrNull()
    }

    override val orphanedAuthenticationHolders: List<AuthenticationHolderEntity>
        get() = getOrphanedAuthenticationHolders(DefaultPageCriteria(pageSize = 1000))

    override fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolderEntity> {
        /*
        "select a from AuthenticationHolderEntity a where " +
                "a.id not in (select t.authenticationHolder.id from OAuth2AccessTokenEntity t) and " +
                "a.id not in (select r.authenticationHolder.id from OAuth2RefreshTokenEntity r) and " +
                "a.id not in (select c.authenticationHolder.id from AuthorizationCodeEntity c)"
         */
        return transaction {
            val ah = AuthenticationHolders
            val at = AccessTokens
            val rt = RefreshTokens
            val ac = AuthorizationCodes

            ah.selectAll().where {
                (ah.id notInSubQuery (at.select(at.authHolderId).withDistinct())) and
                        ((ah.id notInSubQuery (rt.select(rt.authHolderId).withDistinct())) and
                                (ah.id notInSubQuery (ac.select(ac.authHolderId).withDistinct())))
            }.map { it.toAuthenticationHolder() }
        }
    }

    override fun save(a: AuthenticationHolderEntity): AuthenticationHolderEntity = transaction {
        val oldId = a.id

        val id = AuthenticationHolders.save(a.id) { b ->
            b[userAuthId] = a.userAuth?.id
            b[approved] = a.isApproved
            b[redirectUri] = a.redirectUri
            b[clientId] = a.clientId
        }

        if (oldId!=null) {
            AuthenticationHolderAuthorities.deleteWhere { ownerId eq oldId }
            AuthenticationHolderResourceIds.deleteWhere { ownerId eq oldId }
            AuthenticationHolderResponseTypes.deleteWhere { ownerId eq oldId }
            AuthenticationHolderExtensions.deleteWhere { ownerId eq oldId }
            AuthenticationHolderScopes.deleteWhere { ownerId eq oldId }
            AuthenticationHolderRequestParameters.deleteWhere { ownerId eq oldId }
        }
        with (AuthenticationHolderAuthorities) {
            saveStrings(a.authorities?.map { it.authority }, this, ownerId, id, authority)
        }

        with(AuthenticationHolderResourceIds) {
            saveStrings(a.resourceIds, this, ownerId, id, resourceId)
        }

        with(AuthenticationHolderResponseTypes) {
            saveStrings(a.responseTypes, this, ownerId, id, responseType)
        }

        with(AuthenticationHolderScopes) {
            saveStrings(a.scope, this, ownerId, id, scope)
        }

        AuthenticationHolderExtensions.let { t ->
            a.extensions?.takeIf { it.isNotEmpty() }?.let { m ->
                t.batchInsert(m.entries) { (k, v) ->
                    this[t.ownerId] = id
                    this[t.extension] = k
                    this[t.value] = v as? String ?: v.toString()
                }
            }
        }

        AuthenticationHolderRequestParameters.let { t ->
            a.requestParameters?.takeIf { it.isNotEmpty() }?.let { m ->
                t.batchInsert(m.entries) { (k, v) ->
                    this[t.ownerId] = id
                    this[t.param] = k
                    this[t.value] = v
                }
            }
        }

        a.copy(id=id)
    }

    override fun remove(a: AuthenticationHolderEntity) {
        val entityId = a.id ?: return

        transaction(database) {
            AuthenticationHolderAuthorities.deleteWhere { ownerId eq entityId }
            AuthenticationHolderResourceIds.deleteWhere { ownerId eq entityId }
            AuthenticationHolderResponseTypes.deleteWhere { ownerId eq entityId }
            AuthenticationHolderExtensions.deleteWhere { ownerId eq entityId }
            AuthenticationHolderScopes.deleteWhere { ownerId eq entityId }
            AuthenticationHolderRequestParameters.deleteWhere { ownerId eq entityId }

            AuthenticationHolders.deleteWhere { id eq entityId }

        }
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
            .map { GrantedAuthority(it[authority]) }
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
        .map { GrantedAuthority(it[authority]!!) } }

    return with(SavedUserAuths) {
        SavedUserAuthentication(
            name = r[name]!!,
            id = savedUserId,
            authorities = authorities,
            authenticated = r[authenticated],
            sourceClass = r[sourceClass]
        )
    }

}
