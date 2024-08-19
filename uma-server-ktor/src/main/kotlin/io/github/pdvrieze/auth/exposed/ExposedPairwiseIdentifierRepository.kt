package io.github.pdvrieze.auth.exposed

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository

class ExposedPairwiseIdentifierRepository(database: Database) : RepositoryBase(database, PairwiseIdentifiers), PairwiseIdentifierRepository {

    override fun getBySectorIdentifier(sub: String, sectorIdentifierUri: String): PairwiseIdentifier? {
        val t = PairwiseIdentifiers
        return t.selectAll()
            .where {
                (t.sub eq sub) and
                    (t.sectorIdentifier eq sectorIdentifierUri)
            }.map { PairwiseIdentifier(it[t.identifier]!!.toLong(), it[t.sub]!!, it[t.sectorIdentifier]!!) }
            .singleOrNull()
    }

    override fun save(pairwise: PairwiseIdentifier): PairwiseIdentifier {
        val t = PairwiseIdentifiers
        val oldId = pairwise.id
        return transaction {
            val newId = t.save(oldId) { b ->
                b[sub] = pairwise.userSub
                b[sectorIdentifier] = pairwise.sectorIdentifier
            }
            pairwise.id = newId
            pairwise.copy(id = newId)
        }
    }
}
