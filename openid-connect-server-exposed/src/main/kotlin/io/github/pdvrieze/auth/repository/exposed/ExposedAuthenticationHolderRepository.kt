package io.github.pdvrieze.auth.repository.exposed

import io.github.pdvrieze.auth.SavedAuthentication
import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.data.DefaultPageCriteria
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolder
import org.mitre.oauth2.model.KtorAuthenticationHolder
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OldSavedUserAuthentication
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import java.time.Instant

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

    override val all: List<AuthenticationHolder>
        get() = transaction {
            AuthenticationHolders.selectAll().map {
                it.toAuthenticationHolder()
            }
        }

    override fun getById(id: Long): AuthenticationHolder? = transaction {
        AuthenticationHolders.selectAll().where { AuthenticationHolders.id eq id }.map {
            it.toAuthenticationHolder()
        }.singleOrNull()
    }

    override val orphanedAuthenticationHolders: List<AuthenticationHolder>
        get() = getOrphanedAuthenticationHolders(DefaultPageCriteria(pageSize = 1000))

    override fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolder> {
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

    override fun save(a: AuthenticationHolder): AuthenticationHolder = transaction {
        val oldId = a.id

        val inputUserAuth = a.subjectAuth
        val userName = inputUserAuth?.principalName

        val userAuth: OldSavedUserAuthentication?
        if (userName != null) {
            val isAuth = inputUserAuth.authTime.isAfter(Instant.EPOCH)
            val userAuthId =
                SavedUserAuths.select(SavedUserAuths.id)
                    .where {
                        (SavedUserAuths.name eq userName)
                            .and {
                                when {
                                    isAuth -> SavedUserAuths.authTime.isNotNull()
                                    else -> SavedUserAuths.authTime.isNull()
                                }
                            }
                    }.singleOrNull()
                    ?.get(SavedUserAuths.id)
                    ?: SavedUserAuths.insertAndGetId {
                        it[this.name] = userName
                        it[this.authTime] = when {
                            isAuth -> inputUserAuth.authTime
                            else -> null
                        }
                    }
            userAuth = OldSavedUserAuthentication(name = userName, id = userAuthId.value)
        } else {
            userAuth = null
        }

        val actualUserAuthId = userAuth?.id

        val id = AuthenticationHolders.save(a.id) { b ->
            b[userAuthId] = actualUserAuthId
            val r = a.authorizationRequest
            b[approved] = r.isApproved
            b[redirectUri] = r.redirectUri
            b[clientId] = r.clientId
            b[requestTime] = r.requestTime
        }

        if (oldId!=null) {
            AuthenticationHolderAuthorities.deleteWhere { ownerId eq oldId }
            AuthenticationHolderResourceIds.deleteWhere { ownerId eq oldId }
            AuthenticationHolderResponseTypes.deleteWhere { ownerId eq oldId }
            AuthenticationHolderExtensions.deleteWhere { ownerId eq oldId }
            AuthenticationHolderScopes.deleteWhere { ownerId eq oldId }
            AuthenticationHolderRequestParameters.deleteWhere { ownerId eq oldId }
        }
        val r = a.authorizationRequest
        with (AuthenticationHolderAuthorities) {
            saveStrings(r.authorities.map { it.authority }, this, ownerId, id, authority)
        }

        with(AuthenticationHolderResourceIds) {
            saveStrings(r.resourceIds, this, ownerId, id, resourceId)
        }

        with(AuthenticationHolderResponseTypes) {
            saveStrings(r.responseTypes, this, ownerId, id, responseType)
        }

        with(AuthenticationHolderScopes) {
            saveStrings(r.scope, this, ownerId, id, scope)
        }

        AuthenticationHolderExtensions.let { t ->
            @OptIn(InternalForStorage::class)
            r.authHolderExtensions.takeIf { it.isNotEmpty() }?.let { m ->
                t.batchInsert(m.entries) { (k, v) ->
                    this[t.ownerId] = id
                    this[t.extension] = k
                    this[t.value] = v
                }
            }
        }

        @OptIn(InternalForStorage::class)
        AuthenticationHolderRequestParameters.let { t ->
            r.requestParameters.takeIf { it.isNotEmpty() }?.let { m ->
                t.batchInsert(m.entries) { (k, v) ->
                    this[t.ownerId] = id
                    this[t.param] = k
                    this[t.value] = v
                }
            }
        }

        a.copy(id =id)
    }

    override fun remove(a: AuthenticationHolder) {
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

private fun ResultRow.toAuthenticationHolder(): AuthenticationHolder {
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
            .mapTo(HashSet()) { LocalGrantedAuthority(it[authority]) }
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



    @OptIn(InternalForStorage::class)
    return with(AuthenticationHolders) {
        val clientId = r[clientId]
        val authReq = when {
            "openid" in scope -> OpenIdAuthorizationRequest.Builder(clientId)
            else -> PlainAuthorizationRequest.Builder(clientId)
        }.also { b ->
            b.setFromExtensions(extensions)
            b.authorities = authorities
            b.resourceIds = resourceIds
            b.redirectUri = r[redirectUri]
            b.responseTypes = responseTypes
            b.clientId = clientId
            b.scope = scope
            b.requestParameters = requestParameters
            b.requestTime = r[requestTime]
        }.build()

        KtorAuthenticationHolder(userAuth, authReq, authHolderId)
    }
}

private fun ResultRow.toUserAuth(): SavedAuthentication {
    val r = this
    val savedUserId = r[SavedUserAuths.id].value

    val authorities = with(SavedUserAuthAuthorities) {
        selectAll().where { ownerId eq savedUserId }
        .map { LocalGrantedAuthority(it[authority]!!) } }

    return with(SavedUserAuths) {
        SavedAuthentication(
            principalName = r[name]!!,
            id = savedUserId,
            authTime = r[authTime] ?: Instant.EPOCH,
            authorities = authorities,
            scope = emptySet(),
            sourceClass = r[sourceClass],
        )
    }

}
