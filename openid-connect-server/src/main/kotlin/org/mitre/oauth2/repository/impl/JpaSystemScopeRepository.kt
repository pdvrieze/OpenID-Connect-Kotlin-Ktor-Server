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
package org.mitre.oauth2.repository.impl

import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.util.toJavaId
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository("jpaSystemScopeRepository")
class JpaSystemScopeRepository : SystemScopeRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    @get:Transactional(value = "defaultTransactionManager")
    override val all: Set<SystemScope>
        /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#getAll()
	 */ get() {
            val query = em.createNamedQuery(SystemScope.QUERY_ALL, SystemScope::class.java)

            return LinkedHashSet(query.resultList)
        }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#getById(java.lang.Long)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun getById(id: java.lang.Long): SystemScope? {
        return em.find(SystemScope::class.java, id)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#getByValue(java.lang.String)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun getByValue(value: String): SystemScope? {
        val query = em.createNamedQuery(SystemScope.QUERY_BY_VALUE, SystemScope::class.java)
        query.setParameter(SystemScope.PARAM_VALUE, value)
        return getSingleResult(query.resultList)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#remove(org.mitre.oauth2.model.SystemScope)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun remove(scope: SystemScope) {
        val found = getById(scope.id.toJavaId())

        if (found != null) {
            em.remove(found)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#save(org.mitre.oauth2.model.SystemScope)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(scope: SystemScope): SystemScope? {
        val id = requireNotNull(scope.id) { "missing id in scope" }
        return saveOrUpdate<SystemScope, Long>(id, em, scope)
    }
}
