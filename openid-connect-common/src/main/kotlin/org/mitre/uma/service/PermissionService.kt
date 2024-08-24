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
package org.mitre.uma.service

import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet

/**
 * @author jricher
 */
interface PermissionService {
    /**
     * @param resourceSet the resource set to create the permission on
     * @param scopes the set of scopes that this permission is for
     * @return the created (and stored) permission object, with ticket
     * @throws InsufficientScopeException if the scopes in scopes don't match those in resourceSet.getScopes
     */
    fun createTicket(resourceSet: ResourceSet, scopes: Set<String>): PermissionTicket?

    /**
     * Read the permission associated with the given ticket.
     *
     * @param ticket the ticket value to search on
     * @return the permission object, or null if none is found
     */
    fun getByTicket(ticket: String): PermissionTicket?

    /**
     * Save the updated permission ticket to the database. Does not create a new ticket.
     */
    fun updateTicket(ticket: PermissionTicket): PermissionTicket?
}
