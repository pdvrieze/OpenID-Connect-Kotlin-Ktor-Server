package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.selectAll
import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository

class ExposedPairwiseIdentifierRepository(database: Database) : RepositoryBase(database, PairwiseIdentifiers), PairwiseIdentifierRepository {

    override fun getBySectorIdentifier(sub: String, sectorIdentifierUri: String): PairwiseIdentifier? {
        val t = PairwiseIdentifiers
        return transaction {
            t.selectAll()
                .where {
                    (PairwiseIdentifiers.sub eq sub) and
                            (PairwiseIdentifiers.sectorIdentifier eq sectorIdentifierUri)
                }
                .map { PairwiseIdentifier(
                    identifier = it[PairwiseIdentifiers.identifier],
                    userSubject = it[PairwiseIdentifiers.sub]!!,
                    sectorIdentifier = it[PairwiseIdentifiers.sectorIdentifier]!!
                ) }
                .singleOrNull()
        }
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
