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
package org.mitre.openid.connect.service

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.openid.connect.model.ApprovedSite
import org.springframework.security.oauth2.provider.ClientDetails
import java.util.*

/**
 * Interface for ApprovedSite service
 *
 * @author Michael Joseph Walsh, aanganes
 */
interface ApprovedSiteService {
    fun createApprovedSite(
        clientId: String?,
        userId: String?,
        timeoutDate: Date?,
        allowedScopes: Set<String>?
    ): ApprovedSite

    /**
     * Return a collection of all ApprovedSites
     *
     * @return the ApprovedSite collection, or null
     */
    val all: Collection<ApprovedSite>?

    /**
     * Return a collection of ApprovedSite managed by this repository matching the
     * provided client ID and user ID
     *
     */
    fun getByClientIdAndUserId(clientId: String, userId: String): Collection<ApprovedSite>?

    /**
     * Save an ApprovedSite
     *
     * the ApprovedSite to be saved
     */
    fun save(approvedSite: ApprovedSite): ApprovedSite?

    /**
     * Get ApprovedSite for id
     *
     * id for ApprovedSite
     * @return ApprovedSite for id, or null
     */
    fun getById(id: Long): ApprovedSite?

    /**
     * Remove the ApprovedSite
     *
     * the ApprovedSite to remove
     */
    fun remove(approvedSite: ApprovedSite)

    /**
     * Get all sites approved by this user
     */
    fun getByUserId(userId: String): Collection<ApprovedSite>?

    /**
     * Get all sites associated with this client
     */
    fun getByClientId(clientId: String): Collection<ApprovedSite>?

    /**
     * Clear out any approved sites for a given client.
     */
    fun clearApprovedSitesForClient(client: ClientDetails)

    /**
     * Remove all expired approved sites from the data store.
     */
    fun clearExpiredSites()

    /**
     * Return all approved access tokens for the site.
     */
    fun getApprovedAccessTokens(approvedSite: ApprovedSite): List<OAuth2AccessTokenEntity>
}
