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
