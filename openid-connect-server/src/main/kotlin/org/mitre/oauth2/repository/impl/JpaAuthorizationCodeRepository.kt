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

import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthorizationCodeEntity
import org.mitre.oauth2.repository.AuthorizationCodeRepository
import org.mitre.util.jpa.JpaUtil.getResultPage
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.util.*
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * JPA AuthorizationCodeRepository implementation.
 *
 * @author aanganes
 */
@Repository
@Transactional(value = "defaultTransactionManager")
class JpaAuthorizationCodeRepository : AuthorizationCodeRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    lateinit var manager: EntityManager

    @Transactional(value = "defaultTransactionManager")
    override fun save(authorizationCode: AuthorizationCodeEntity): AuthorizationCodeEntity? {
        return saveOrUpdate(authorizationCode.id, manager, authorizationCode)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.AuthorizationCodeRepository#getByCode(java.lang.String)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun getByCode(code: String): AuthorizationCodeEntity? {
        val query =
            manager.createNamedQuery(AuthorizationCodeEntity.QUERY_BY_VALUE, AuthorizationCodeEntity::class.java)
        query.setParameter("code", code)

        val result = getSingleResult(query.resultList)
        return result
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.AuthorizationCodeRepository#remove(org.mitre.oauth2.model.AuthorizationCodeEntity)
	 */
    override fun remove(authorizationCodeEntity: AuthorizationCodeEntity) {
        val found = manager.find(AuthorizationCodeEntity::class.java, authorizationCodeEntity.id)
        if (found != null) {
            manager.remove(found)
        }
    }

    override val expiredCodes: Collection<AuthorizationCodeEntity>
        /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.AuthorizationCodeRepository#getExpiredCodes()
	 */
        get() {
            val query =
                manager.createNamedQuery(AuthorizationCodeEntity.QUERY_EXPIRATION_BY_DATE, AuthorizationCodeEntity::class.java)
            query.setParameter(AuthorizationCodeEntity.PARAM_DATE, Date()) // this gets anything that's already expired
            return query.resultList
        }


    override fun getExpiredCodes(pageCriteria: PageCriteria): Collection<AuthorizationCodeEntity> {
        val query =
            manager.createNamedQuery(AuthorizationCodeEntity.QUERY_EXPIRATION_BY_DATE, AuthorizationCodeEntity::class.java)
        query.setParameter(AuthorizationCodeEntity.PARAM_DATE, Date()) // this gets anything that's already expired
        return getResultPage(query, pageCriteria)
    }
}
