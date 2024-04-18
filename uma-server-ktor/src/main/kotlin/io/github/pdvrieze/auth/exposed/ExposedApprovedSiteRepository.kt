package io.github.pdvrieze.auth.exposed

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import java.util.Date

class ExposedApprovedSiteRepository(database: Database): RepositoryBase(database, ApprovedSites, ApprovedSiteScopes), ApprovedSiteRepository {

    override fun getById(id: Long): ApprovedSite? = transaction {
        ApprovedSites.selectAll().where { ApprovedSites.id eq id }
            .singleOrNull()
            ?.toApprovedSite()
    }

    override val all: Collection<ApprovedSite>
        get() = transaction {
            ApprovedSites.selectAll().map { it.toApprovedSite() }
        }

    override fun getByClientIdAndUserId(clientId: String, userId: String): Collection<ApprovedSite> = transaction {
        ApprovedSites.selectAll()
            .where { (ApprovedSites.clientId eq clientId) and (ApprovedSites.userId eq userId) }
            .map { it.toApprovedSite() }
    }

    override fun getByUserId(userId: String): Collection<ApprovedSite> = transaction {
        ApprovedSites.selectAll()
            .where { ApprovedSites.userId eq userId }
            .map { it.toApprovedSite() }
    }

    override fun getByClientId(clientId: String): Collection<ApprovedSite> = transaction {
        ApprovedSites.selectAll()
            .where { ApprovedSites.clientId eq clientId }
            .map { it.toApprovedSite() }
    }

    override fun remove(approvedSite: ApprovedSite) {
        val siteId = requireNotNull(approvedSite.id)
        transaction {
            ApprovedSites.deleteWhere { id eq siteId }
        }
    }

    override fun save(approvedSite: ApprovedSite): ApprovedSite = transaction {
        val v = approvedSite
        val oldId = approvedSite.id
        val newId = ApprovedSites.save(oldId) { b ->
            b[userId] = v.userId
            b[clientId] = v.clientId
            b[creationDate] = v.creationDate?.toInstant()
            b[accessDate] = v.accessDate?.toInstant()
            b[timeoutDate] = v.timeoutDate?.toInstant()
        }

        if (oldId != null) {
            ApprovedSiteScopes.deleteWhere { ownerId eq oldId }
        }

        ApprovedSiteScopes.batchInsert(approvedSite.allowedScopes) { scope ->
            this[ApprovedSiteScopes.ownerId] = newId
            this[ApprovedSiteScopes.scope] = scope
        }

        approvedSite.apply { id = newId }
    }
}

private fun ResultRow.toApprovedSite(): ApprovedSite {
    val r = this
    with(ApprovedSites) {
        val siteId = r[id].value
        val allowedScopes = with(ApprovedSiteScopes) {
            select(scope).where { ownerId eq siteId }.mapTo(HashSet()) { it[scope] }
        }
        return ApprovedSite(
            id = siteId,
            userId = r[userId],
            clientId = r[clientId],
            creationDate = r[creationDate]?.let { Date.from(it) },
            accessDate = r[accessDate]?.let { Date.from(it) },
            timeoutDate = r[timeoutDate]?.let { Date.from(it) },
            allowedScopes = allowedScopes,
        )
    }

}
