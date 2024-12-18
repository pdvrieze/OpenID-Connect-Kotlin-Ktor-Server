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

import org.mitre.oauth2.exception.InsufficientScopeException
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.service.PermissionService
import java.sql.Date
import java.util.*

/**
 * @author jricher
 */
class DefaultPermissionService(
    private val repository: PermissionRepository,
    private val scopeService: SystemScopeService,
    private val permissionExpirationSeconds: Long = 60L * 60L, // 1 hr
) : PermissionService {

    /* (non-Javadoc)
	 * @see org.mitre.uma.service.PermissionService#create(org.mitre.uma.model.ResourceSet, java.util.Set)
	 */
    override fun createTicket(resourceSet: ResourceSet, scopes: Set<String>): PermissionTicket? {
        // check to ensure that the scopes requested are a subset of those in the resource set

        if (!scopeService.scopesMatch(resourceSet.scopes, scopes)) {
            throw InsufficientScopeException("Scopes of resource set are not enough for requested permission.")
        }

        val ticket = PermissionTicket(
            permission = Permission(resourceSet = resourceSet, scopes = scopes),
            expiration = Date(System.currentTimeMillis() + permissionExpirationSeconds * 1000L),
            ticket = UUID.randomUUID().toString(),
        )

        return repository.save(ticket)
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.service.PermissionService#getByTicket(java.lang.String)
	 */
    override fun getByTicket(ticket: String): PermissionTicket? {
        return repository.getByTicket(ticket)
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.service.PermissionService#updateTicket(org.mitre.uma.model.PermissionTicket)
	 */
    override fun updateTicket(ticket: PermissionTicket): PermissionTicket? {
        return when {
            ticket.id != null -> repository.save(ticket)
            else -> null
        }
    }
}
