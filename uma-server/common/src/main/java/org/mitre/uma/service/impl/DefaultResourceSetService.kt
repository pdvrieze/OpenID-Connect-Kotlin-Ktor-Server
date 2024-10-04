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

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.uma.model.ResourceSet
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Primary
import org.springframework.stereotype.Service

/**
 * @author jricher
 */
@Service
@Primary
class DefaultResourceSetService : org.mitre.uma.service.ResourceSetService {
    @Autowired
    private lateinit var repository: org.mitre.uma.repository.ResourceSetRepository

    @Autowired
    private lateinit var tokenRepository: org.mitre.oauth2.repository.OAuth2TokenRepository

    @Autowired
    private lateinit var ticketRepository: org.mitre.uma.repository.PermissionRepository

    @Deprecated("JPA only")
    constructor()

    constructor(
        repository: org.mitre.uma.repository.ResourceSetRepository,
        tokenRepository: org.mitre.oauth2.repository.OAuth2TokenRepository,
        ticketRepository: org.mitre.uma.repository.PermissionRepository,
    ) {
        this.repository = repository
        this.tokenRepository = tokenRepository
        this.ticketRepository = ticketRepository
    }

    override fun saveNew(rs: ResourceSet): ResourceSet {
        require(rs.id == null) { "Can't save a new resource set with an ID already set to it." }

        require(checkScopeConsistency(rs)) { "Can't save a resource set with inconsistent claims." }

        val saved = repository.save(rs)

        return saved
    }

    override fun getById(id: Long): ResourceSet? {
        return repository.getById(id)
    }

    override fun update(oldRs: ResourceSet, newRs: ResourceSet): ResourceSet {
        require(!(oldRs.id == null || newRs.id == null || oldRs.id != newRs.id)) { "Resource set IDs mismatched" }

        require(checkScopeConsistency(newRs)) { "Can't save a resource set with inconsistent claims." }

        newRs.owner = oldRs.owner // preserve the owner tag across updates
        newRs.clientId = oldRs.clientId // preserve the client id across updates

        val saved = repository.save(newRs)

        return saved
    }

    override fun remove(rs: ResourceSet?) {
        // find all the access tokens issued against this resource set and revoke them
        val tokens: Collection<OAuth2AccessTokenEntity> = tokenRepository.getAccessTokensForResourceSet(rs!!)
        for (token in tokens) {
            tokenRepository.removeAccessToken(token)
        }

        // find all outstanding tickets issued against this resource set and revoke them too
        val tickets = ticketRepository.getPermissionTicketsForResourceSet(rs)
        for (ticket in tickets!!) {
            ticketRepository.remove(ticket)
        }

        repository.remove(rs)
    }

    override fun getAllForOwner(owner: String): Collection<ResourceSet> {
        return repository.getAllForOwner(owner)
    }

    override fun getAllForOwnerAndClient(owner: String, clientId: String): Collection<ResourceSet> {
        return repository.getAllForOwnerAndClient(owner, clientId)
    }

    private fun checkScopeConsistency(rs: ResourceSet): Boolean {
        if (rs.policies == null) {
            // nothing to check, no problem!
            return true
        }
        for (policy in rs.policies!!) {
            if (!rs.scopes.containsAll(policy.scopes!!)) {
                return false
            }
        }
        // we've checked everything, we're good
        return true
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.service.ResourceSetService#getAllForClient(org.mitre.oauth2.model.ClientDetailsEntity)
	 */
    override fun getAllForClient(client: OAuthClientDetails): Collection<ResourceSet> {
        val clientId = requireNotNull(client.clientId) { "missing client id in entity" }
        return repository.getAllForClient(clientId)
    }

    companion object {
        private val logger = getLogger<DefaultResourceSetService>()
    }
}
