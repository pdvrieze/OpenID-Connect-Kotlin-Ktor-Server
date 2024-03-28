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

import org.mitre.data.DefaultPageCriteria
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.util.jpa.JpaUtil.getResultPage
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

@Repository
@Transactional(value = "defaultTransactionManager")
class JpaAuthenticationHolderRepository : AuthenticationHolderRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    override val all: List<AuthenticationHolderEntity>
        get() {
            val query =
                manager.createNamedQuery(AuthenticationHolderEntity.QUERY_ALL, AuthenticationHolderEntity::class.java)
            return query.resultList
        }

    override fun getById(id: Long?): AuthenticationHolderEntity? {
        return manager.find(AuthenticationHolderEntity::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun remove(a: AuthenticationHolderEntity) {
        val found = getById(a.id)
        if (found != null) {
            manager.remove(found)
        } else {
            throw IllegalArgumentException("AuthenticationHolderEntity not found: $a")
        }
    }

    @Transactional(value = "defaultTransactionManager")
    override fun save(a: AuthenticationHolderEntity): AuthenticationHolderEntity {
        return saveOrUpdate(a.id, manager, a)
    }

    @get:Transactional(value = "defaultTransactionManager")
    override val orphanedAuthenticationHolders: List<AuthenticationHolderEntity>
        get() {
            val pageCriteria = DefaultPageCriteria(0, MAXEXPIREDRESULTS)
            return getOrphanedAuthenticationHolders(pageCriteria)
        }

    @Transactional(value = "defaultTransactionManager")
    override fun getOrphanedAuthenticationHolders(pageCriteria: PageCriteria): List<AuthenticationHolderEntity> {
        val query =
            manager.createNamedQuery(AuthenticationHolderEntity.QUERY_GET_UNUSED, AuthenticationHolderEntity::class.java)
        return getResultPage(query, pageCriteria)
    }

    companion object {
        private const val MAXEXPIREDRESULTS = 1000
    }
}
