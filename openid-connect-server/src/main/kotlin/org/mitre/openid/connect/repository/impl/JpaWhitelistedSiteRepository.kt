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

import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * JPA WhitelistedSite repository implementation
 *
 * @author Michael Joseph Walsh, aanganes
 */
@Repository
class JpaWhitelistedSiteRepository : WhitelistedSiteRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    @get:Transactional(value = "defaultTransactionManager")
    override val all: Collection<WhitelistedSite>
        get() {
            val query = manager.createNamedQuery(WhitelistedSite.QUERY_ALL, WhitelistedSite::class.java)
            return query.resultList
        }

    @Transactional(value = "defaultTransactionManager")
    override fun getById(id: Long): WhitelistedSite {
        return manager.find(WhitelistedSite::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun remove(whitelistedSite: WhitelistedSite) {
        val found = requireNotNull(manager.find(WhitelistedSite::class.java, whitelistedSite.id))

        manager.remove(found)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun save(whiteListedSite: WhitelistedSite): WhitelistedSite {
        return saveOrUpdate(whiteListedSite.id!!, manager, whiteListedSite)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun update(oldWhitelistedSite: WhitelistedSite, whitelistedSite: WhitelistedSite): WhitelistedSite {
        // sanity check
        whitelistedSite.id = oldWhitelistedSite.id

        return saveOrUpdate(oldWhitelistedSite.id!!, manager, whitelistedSite)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun getByClientId(clientId: String): WhitelistedSite? {
        return manager.createNamedQuery(WhitelistedSite.QUERY_BY_CLIENT_ID, WhitelistedSite::class.java).run {
            setParameter(WhitelistedSite.PARAM_CLIENT_ID, clientId)
            getSingleResult(resultList)
        }
    }

    @Transactional(value = "defaultTransactionManager")
    override fun getByCreator(creatorId: String): Collection<WhitelistedSite>? {
        return manager.createNamedQuery(WhitelistedSite.QUERY_BY_CREATOR, WhitelistedSite::class.java).run {
            setParameter(WhitelistedSite.PARAM_USER_ID, creatorId)
            resultList
        }
    }
}
