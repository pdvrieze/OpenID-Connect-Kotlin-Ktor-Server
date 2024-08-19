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

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.util.requireId
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
@Transactional(value = "defaultTransactionManager")
class JpaOAuth2ClientRepository : OAuth2ClientRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var manager: EntityManager

    constructor()

    constructor(manager: EntityManager) {
        this.manager = manager
    }

    override fun getById(id: Long): ClientDetailsEntity? {
        return manager.find(ClientDetailsEntity::class.java, id)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.OAuth2ClientRepository#getClientById(java.lang.String)
	 */
    override fun getClientByClientId(clientId: String): ClientDetailsEntity? {
        val query = manager.createNamedQuery(ClientDetailsEntity.QUERY_BY_CLIENT_ID, ClientDetailsEntity::class.java)
        query.setParameter(ClientDetailsEntity.PARAM_CLIENT_ID, clientId)
        return getSingleResult(query.resultList)
    }

    override fun saveClient(client: OAuthClientDetails): OAuthClientDetails {
        return saveOrUpdate(client.getClientId(), manager, client)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.OAuth2ClientRepository#deleteClient(org.mitre.oauth2.model.ClientDetailsEntity)
	 */

    override fun deleteClient(client: OAuthClientDetails) {
        val found = getById(client.id.requireId())
        if (found != null) {
            manager.remove(found)
        } else {
            throw IllegalArgumentException("Client not found: $client")
        }
    }

    override fun updateClient(id: Long, client: OAuthClientDetails): OAuthClientDetails {
        return saveOrUpdate(id, manager, client).also {
            // sanity check
            assert(it.id == id)
        }
    }

    override val allClients: Collection<ClientDetailsEntity>
        get() {
            val query = manager.createNamedQuery(ClientDetailsEntity.QUERY_ALL, ClientDetailsEntity::class.java)
            return query.resultList
        }
}
