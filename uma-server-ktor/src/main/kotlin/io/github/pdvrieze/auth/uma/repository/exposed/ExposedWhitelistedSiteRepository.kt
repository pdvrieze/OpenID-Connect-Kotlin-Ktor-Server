package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import io.github.pdvrieze.auth.repository.exposed.WhitelistedSiteScopes
import io.github.pdvrieze.auth.repository.exposed.WhitelistedSites
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.WhitelistedSiteRepository

class ExposedWhitelistedSiteRepository(database: Database)
    : RepositoryBase(database, WhitelistedSites, WhitelistedSiteScopes), WhitelistedSiteRepository {

    override val all: Collection<WhitelistedSite>
        get() = transaction {
            WhitelistedSites.selectAll()
                .map { it.toWhitelistedSite() }
        }

    override fun getById(id: Long): WhitelistedSite? = transaction {
        WhitelistedSites.selectAll()
            .where { WhitelistedSites.id eq id }
            .singleOrNull()
            ?.toWhitelistedSite()
    }

    override fun getByClientId(clientId: String): WhitelistedSite? = transaction {
        WhitelistedSites.selectAll()
            .where { WhitelistedSites.clientId eq clientId }
            .singleOrNull()
            ?.toWhitelistedSite()
    }

    override fun getByCreator(creatorId: String): Collection<WhitelistedSite> = transaction {
        WhitelistedSites.selectAll()
            .where { WhitelistedSites.creatorUserId eq creatorId }
            .map { it.toWhitelistedSite() }
    }

    override fun remove(whitelistedSite: WhitelistedSite) {
        val siteId = whitelistedSite.id
        WhitelistedSites.deleteWhere { id eq siteId }
    }

    override fun save(whiteListedSite: WhitelistedSite): WhitelistedSite = transaction {
        val oldId = whiteListedSite.id

        val newId = WhitelistedSites.save(oldId) { b ->
            b[creatorUserId] = whiteListedSite.creatorUserId
            b[clientId] = whiteListedSite.clientId
        }

        if (oldId != null) {
            WhitelistedSiteScopes.deleteWhere { ownerId eq oldId }
        }

        WhitelistedSiteScopes.batchInsert(whiteListedSite.allowedScopes) { scope ->
            this[WhitelistedSiteScopes.ownerId] = newId
            this[WhitelistedSiteScopes.scope] = scope
        }

        whiteListedSite.apply { id = newId }
    }

    override fun update(oldWhitelistedSite: WhitelistedSite, whitelistedSite: WhitelistedSite): WhitelistedSite {
        TODO("not implemented")
    }
}

private fun ResultRow.toWhitelistedSite(): WhitelistedSite {
    val r = this
    val siteId = r[WhitelistedSites.id].value

    val allowedScopes = with(WhitelistedSiteScopes) {
        select(scope).where { ownerId eq siteId }.mapTo(HashSet()) { it[scope] }
    }

    with(WhitelistedSites) {
        return WhitelistedSite(
            id = siteId,
            creatorUserId = r[creatorUserId],
            clientId = r[clientId],
            allowedScopes = allowedScopes
        )
    }
}
