/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.repository.impl.jpa

import org.mitre.oauth2.util.requireId
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository
open class JpaResourceSetRepository : ResourceSetRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    @Transactional(value = "defaultTransactionManager")
    override fun save(rs: ResourceSet): ResourceSet {
        return saveOrUpdate(rs.id, em, rs)
    }

    override fun getById(id: Long): ResourceSet? {
        return em.find(ResourceSet::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun remove(rs: ResourceSet) {
        when (val found = getById(rs.id.requireId())) {
            null -> logger.info("Tried to remove unknown resource set: ${rs.id}")
            else -> em.remove(found)
        }
    }

    override fun getAllForOwner(owner: String): Collection<ResourceSet> {
        val query = em.createNamedQuery(ResourceSet.QUERY_BY_OWNER, ResourceSet::class.java)
        query.setParameter(ResourceSet.PARAM_OWNER, owner)
        return query.resultList
    }

    override fun getAllForOwnerAndClient(owner: String, clientId: String): Collection<ResourceSet> {
        val query = em.createNamedQuery(ResourceSet.QUERY_BY_OWNER_AND_CLIENT, ResourceSet::class.java)
        query.setParameter(ResourceSet.PARAM_OWNER, owner)
        query.setParameter(ResourceSet.PARAM_CLIENTID, clientId)
        return query.resultList
    }

    override val all: Collection<ResourceSet>
        get() {
            val query = em.createNamedQuery(ResourceSet.QUERY_ALL, ResourceSet::class.java)
            return query.resultList
        }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.ResourceSetRepository#getAllForClient(org.mitre.oauth2.model.ClientDetailsEntity)
	 */
    override fun getAllForClient(clientId: String): Collection<ResourceSet> {
        val query = em.createNamedQuery(ResourceSet.QUERY_BY_CLIENT, ResourceSet::class.java)
        query.setParameter(ResourceSet.PARAM_CLIENTID, clientId)
        return query.resultList
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(JpaResourceSetRepository::class.java)
    }
}
