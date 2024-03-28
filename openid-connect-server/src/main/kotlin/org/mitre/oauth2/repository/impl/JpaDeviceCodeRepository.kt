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
package org.mitre.oauth2.repository.impl

import org.mitre.oauth2.model.DeviceCode
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.mitre.util.jpa.JpaUtil.saveOrUpdate
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.util.*
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository("jpaDeviceCodeRepository")
class JpaDeviceCodeRepository : DeviceCodeRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    @Transactional(value = "defaultTransactionManager")
    override fun getById(id: java.lang.Long): DeviceCode? {
        return em.find(DeviceCode::class.java, id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun getByUserCode(value: String): DeviceCode? {
        val query = em.createNamedQuery(DeviceCode.QUERY_BY_USER_CODE, DeviceCode::class.java)
        query.setParameter(DeviceCode.PARAM_USER_CODE, value)
        return getSingleResult(query.resultList)
    }

    /* (non-Javadoc)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun getByDeviceCode(value: String): DeviceCode? {
        val query = em.createNamedQuery(DeviceCode.QUERY_BY_DEVICE_CODE, DeviceCode::class.java)
        query.setParameter(DeviceCode.PARAM_DEVICE_CODE, value)
        return getSingleResult(query.resultList)
    }

    /* (non-Javadoc)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun remove(scope: DeviceCode) {
        val found = getById((scope.id as java.lang.Long?) ?: return)

        if (found != null) {
            em.remove(found)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.SystemScopeRepository#save(org.mitre.oauth2.model.SystemScope)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(scope: DeviceCode): DeviceCode? {
        val id = requireNotNull(scope.id) { "Null id in scope" }
        return saveOrUpdate(id, em, scope)
    }

    @get:Transactional(value = "defaultTransactionManager")
    override val expiredCodes: Collection<DeviceCode>
        /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.impl.DeviceCodeRepository#getExpiredCodes()
	 */ get() {
            val query = em.createNamedQuery(DeviceCode.QUERY_EXPIRED_BY_DATE, DeviceCode::class.java)
            query.setParameter(DeviceCode.PARAM_DATE, Date())
            return query.resultList
        }
}
