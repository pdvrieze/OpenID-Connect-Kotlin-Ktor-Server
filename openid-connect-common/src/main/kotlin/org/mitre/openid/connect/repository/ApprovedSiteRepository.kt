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
package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.ApprovedSite

/**
 * ApprovedSite repository interface
 *
 * @author Michael Joseph Walsh, aanganes
 */
interface ApprovedSiteRepository {
    /**
     * Returns the ApprovedSite for the given id
     *
     * @param id The id of the ApprovedSite
     * @return a valid ApprovedSite if it exists, null otherwise
     */
    fun getById(id: Long): ApprovedSite?

    /**
     * Return a collection of all ApprovedSites managed by this repository
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
     * Removes the given ApprovedSite from the repository
     *
     * the ApprovedSite object to remove
     */
    fun remove(approvedSite: ApprovedSite)

    /**
     * Persists an ApprovedSite
     *
     * valid ApprovedSite instance
     * @return the persisted entity
     */
    fun save(approvedSite: ApprovedSite): ApprovedSite

    /**
     * Get all sites approved by this user
     */
    fun getByUserId(userId: String): Collection<ApprovedSite>

    /**
     * Get all sites associated with this client
     */
    fun getByClientId(clientId: String): Collection<ApprovedSite>?
}
