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
