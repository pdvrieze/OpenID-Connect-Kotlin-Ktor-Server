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
package org.mitre.uma.service.impl

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.uma.model.SavedRegisteredClient
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.util.jpa.JpaUtil.getSingleResult
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Service
open class JpaRegisteredClientService : RegisteredClientService, SavedRegisteredClientService {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#getByIssuer(java.lang.String)
	 */
    override fun getByIssuer(issuer: String): RegisteredClient? {
        val saved = getSavedRegisteredClientFromStorage(issuer)

        return saved?.registeredClient
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#save(java.lang.String, org.mitre.oauth2.model.RegisteredClient)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(issuer: String, client: RegisteredClient) {
        val saved = getSavedRegisteredClientFromStorage(issuer)
            ?: SavedRegisteredClient().also { it.issuer = issuer }

        saved.registeredClient = client

        em.persist(saved)
    }

    private fun getSavedRegisteredClientFromStorage(issuer: String): SavedRegisteredClient? {
        val query =
            em.createQuery("SELECT c from SavedRegisteredClient c where c.issuer = :issuer", SavedRegisteredClient::class.java)
        query.setParameter("issuer", issuer)

        return getSingleResult(query.resultList)
    }


    override val all: Collection<SavedRegisteredClient>
        get() {
            val query = em.createQuery("SELECT c from SavedRegisteredClient c", SavedRegisteredClient::class.java)
            return query.resultList
        }
}
