package org.mitre.openid.connect.repository.impl

import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.util.jpa.JpaUtil
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository
class JpaPairwiseIdentifierRepository : PairwiseIdentifierRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.PairwiseIdentifierRepository#getBySectorIdentifier(java.lang.String, java.lang.String)
	 */
    override fun getBySectorIdentifier(sub: String, sectorIdentifierUri: String): PairwiseIdentifier? {
        val query =
            manager.createNamedQuery(PairwiseIdentifier.QUERY_BY_SECTOR_IDENTIFIER, PairwiseIdentifier::class.java)
        query.setParameter(PairwiseIdentifier.PARAM_SUB, sub)
        query.setParameter(PairwiseIdentifier.PARAM_SECTOR_IDENTIFIER, sectorIdentifierUri)

        return JpaUtil.getSingleResult(query.resultList)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.PairwiseIdentifierRepository#save(org.mitre.openid.connect.model.PairwiseIdentifier)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(pairwise: PairwiseIdentifier): PairwiseIdentifier {
        return JpaUtil.saveOrUpdate(pairwise.id!!, manager, pairwise)
    }
}
