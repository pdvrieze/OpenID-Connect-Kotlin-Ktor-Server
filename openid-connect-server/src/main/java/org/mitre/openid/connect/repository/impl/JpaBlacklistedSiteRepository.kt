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

import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository
class JpaBlacklistedSiteRepository : BlacklistedSiteRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    @get:Transactional(value = "defaultTransactionManager")
    override val all: Collection<BlacklistedSite>
        get() {
            val query = manager.createNamedQuery(BlacklistedSite.QUERY_ALL, BlacklistedSite::class.java)
            return query.resultList
        }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.BlacklistedSiteRepository#getById(java.lang.Long)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun getById(id: java.lang.Long): BlacklistedSite {
        return manager.find(BlacklistedSite::class.java, id)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.BlacklistedSiteRepository#remove(org.mitre.openid.connect.model.BlacklistedSite)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun remove(blacklistedSite: BlacklistedSite) {
        val found = manager.find(BlacklistedSite::class.java, blacklistedSite.id)

        if (found != null) {
            manager.remove(found)
        } else {
            throw IllegalArgumentException()
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.BlacklistedSiteRepository#save(org.mitre.openid.connect.model.BlacklistedSite)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(blacklistedSite: BlacklistedSite): BlacklistedSite {
        return saveOrUpdate(blacklistedSite.id!!, manager, blacklistedSite)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.BlacklistedSiteRepository#update(org.mitre.openid.connect.model.BlacklistedSite, org.mitre.openid.connect.model.BlacklistedSite)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun update(oldBlacklistedSite: BlacklistedSite, blacklistedSite: BlacklistedSite): BlacklistedSite {
        blacklistedSite.id = oldBlacklistedSite.id
        return saveOrUpdate(oldBlacklistedSite.id!!, manager, blacklistedSite)
    }
}
