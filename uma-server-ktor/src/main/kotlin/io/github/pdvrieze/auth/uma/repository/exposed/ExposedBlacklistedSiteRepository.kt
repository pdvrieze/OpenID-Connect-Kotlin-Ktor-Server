package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.update
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.repository.BlacklistedSiteRepository

class ExposedBlacklistedSiteRepository(database: Database):
    RepositoryBase(database, BlacklistedSites), BlacklistedSiteRepository {

    override val all: Collection<BlacklistedSite>
        get() = transaction { BlacklistedSites.selectAll().map { it.toBlacklistedSite() } }

    override fun getById(id: Long): BlacklistedSite? = transaction {
        BlacklistedSites.selectAll()
            .where { BlacklistedSites.id eq id }
            .singleOrNull()
            ?.toBlacklistedSite()
    }

    override fun remove(blacklistedSite: BlacklistedSite) {
        val siteId = requireNotNull(blacklistedSite.id)
        return transaction {
            BlacklistedSites.deleteWhere { id eq siteId }
        }
    }

    override fun save(blacklistedSite: BlacklistedSite): BlacklistedSite {
        val siteId = blacklistedSite.id
        return transaction {
            val newId = BlacklistedSites.save(siteId) { b ->
                b[uri] = blacklistedSite.uri
            }
            blacklistedSite.apply { id = newId }
        }
    }

    override fun update(oldBlacklistedSite: BlacklistedSite, blacklistedSite: BlacklistedSite): BlacklistedSite = transaction {
        val oldId = requireNotNull(oldBlacklistedSite.id)
        BlacklistedSites.update(where = { BlacklistedSites.id eq oldId }) { s ->
            s[uri] = blacklistedSite.uri
        }

        blacklistedSite.apply { id = oldId }
    }
}

private fun ResultRow.toBlacklistedSite(): BlacklistedSite {
    val r = this
    with (BlacklistedSites) {
        return BlacklistedSite(
            id = r[id].value,
            uri = r[uri]
        )
    }
}
