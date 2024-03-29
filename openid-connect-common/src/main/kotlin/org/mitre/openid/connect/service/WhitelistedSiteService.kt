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

import org.mitre.openid.connect.model.WhitelistedSite

/**
 * Interface for WhitelistedSite service
 *
 * @author Michael Joseph Walsh, aanganes
 */
interface WhitelistedSiteService {
    /**
     * Return a collection of all WhitelistedSite managed by this service
     *
     * @return the WhitelistedSite collection, or null
     */
    val all: Collection<WhitelistedSite>?

    /**
     * Returns the WhitelistedSite for the given id
     *
     * id the id of the WhitelistedSite
     * @return a valid WhitelistedSite if it exists, null otherwise
     */
    fun getById(id: java.lang.Long): WhitelistedSite?

    /**
     * Find a WhitelistedSite by its associated ClientDetails reference
     *
     * @param clientId    the Relying Party
     * @return            the corresponding WhitelistedSite if one exists for the RP, or null
     */
    fun getByClientId(clientId: String): WhitelistedSite?


    /**
     * Removes the given WhitelistedSite from the repository
     *
     * the WhitelistedSite object to remove
     */
    fun remove(whitelistedSite: WhitelistedSite)

    /**
     * Persists a new WhitelistedSite
     *
     * @param whitelistedSite the WhitelistedSite to be saved
     */
    fun saveNew(whitelistedSite: WhitelistedSite): WhitelistedSite

    /**
     * Updates an existing whitelisted site
     */
    fun update(oldWhitelistedSite: WhitelistedSite, whitelistedSite: WhitelistedSite): WhitelistedSite
}
