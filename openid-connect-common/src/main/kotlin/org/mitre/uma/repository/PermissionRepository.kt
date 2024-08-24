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
package org.mitre.uma.repository

import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet

/**
 * @author jricher
 */
interface PermissionRepository {
    /**
     * Save a permission ticket.
     */
    fun save(p: PermissionTicket): PermissionTicket?

    /**
     * Get the permission indicated by its ticket value.
     */
    fun getByTicket(ticket: String): PermissionTicket?

    /**
     * Get all the tickets in the system (used by the import/export API)
     */
    val all: Collection<PermissionTicket>?

    /**
     * Save a permission object with no associated ticket (used by the import/export API)
     */
    fun saveRawPermission(p: Permission): Permission

    /**
     * Get a permission object by its ID (used by the import/export API)
     */
    fun getById(permissionId: Long): Permission?

    /**
     * Get all permission tickets issued against a resource set (called when RS is deleted)
     */
    fun getPermissionTicketsForResourceSet(rs: ResourceSet): Collection<PermissionTicket>?

    /**
     * Remove the specified ticket.
     */
    fun remove(ticket: PermissionTicket)
}
