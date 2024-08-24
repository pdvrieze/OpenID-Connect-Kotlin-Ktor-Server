/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.openid.connect.repository.impl

import org.mitre.openid.connect.model.PairwiseIdentifier
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
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

        return getSingleResult(query.resultList)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.PairwiseIdentifierRepository#save(org.mitre.openid.connect.model.PairwiseIdentifier)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(pairwise: PairwiseIdentifier): PairwiseIdentifier {
        return saveOrUpdate(pairwise.id!!, manager, pairwise)
    }
}
