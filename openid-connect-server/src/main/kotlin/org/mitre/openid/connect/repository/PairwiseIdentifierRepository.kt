package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.PairwiseIdentifier

/**
 * @author jricher
 */
interface PairwiseIdentifierRepository {
    /**
     * Get a pairwise identifier by its associated user subject and sector identifier.
     *
     */
    fun getBySectorIdentifier(sub: String, sectorIdentifierUri: String): PairwiseIdentifier?

    /**
     * Save a pairwise identifier to the database.
     *
     */
    fun save(pairwise: PairwiseIdentifier): PairwiseIdentifier
}
