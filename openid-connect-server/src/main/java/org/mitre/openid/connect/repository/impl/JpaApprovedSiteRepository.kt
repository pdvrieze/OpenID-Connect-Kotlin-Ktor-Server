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

import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * JPA ApprovedSite repository implementation
 *
 * @author Michael Joseph Walsh, aanganes
 */
@Repository
class JpaApprovedSiteRepository : ApprovedSiteRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    @get:Transactional(value = "defaultTransactionManager")
    override val all: Collection<ApprovedSite>
        get() {
            val query = manager.createNamedQuery(ApprovedSite.QUERY_ALL, ApprovedSite::class.java)
            return query.resultList
        }

    @Transactional(value = "defaultTransactionManager")
    override fun getById(id: java.lang.Long): ApprovedSite? {
        return manager.find(ApprovedSite::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun remove(approvedSite: ApprovedSite) {
        val found = manager.find(ApprovedSite::class.java, approvedSite.id)
            ?: throw IllegalArgumentException()

        manager.remove(found)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun save(approvedSite: ApprovedSite): ApprovedSite {
        return saveOrUpdate<ApprovedSite, Long>(approvedSite.id!!, manager, approvedSite)
    }

    override fun getByClientIdAndUserId(clientId: String?, userId: String?): Collection<ApprovedSite>? {
        val query = manager.createNamedQuery(ApprovedSite.QUERY_BY_CLIENT_ID_AND_USER_ID, ApprovedSite::class.java)
        query.setParameter(ApprovedSite.PARAM_USER_ID, userId)
        query.setParameter(ApprovedSite.PARAM_CLIENT_ID, clientId)

        return query.resultList
    }

    @Transactional(value = "defaultTransactionManager")
    override fun getByUserId(userId: String): Collection<ApprovedSite> {
        val query = manager.createNamedQuery(ApprovedSite.QUERY_BY_USER_ID, ApprovedSite::class.java)
        query.setParameter(ApprovedSite.PARAM_USER_ID, userId)

        return query.resultList
    }

    @Transactional(value = "defaultTransactionManager")
    override fun getByClientId(clientId: String): Collection<ApprovedSite>? {
        val query = manager.createNamedQuery(ApprovedSite.QUERY_BY_CLIENT_ID, ApprovedSite::class.java)
        query.setParameter(ApprovedSite.PARAM_CLIENT_ID, clientId)

        return query.resultList
    }
}
