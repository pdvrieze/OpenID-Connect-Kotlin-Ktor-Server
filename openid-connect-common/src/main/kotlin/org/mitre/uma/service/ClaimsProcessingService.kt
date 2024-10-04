package org.mitre.uma.service

import org.mitre.uma.model.ClaimProcessingResult
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet

/**
 *
 * Processes claims presented during an UMA transaction.
 *
 * @author jricher
 */
interface ClaimsProcessingService {
    /**
     * Determine whether or not the claims that have been supplied are
     * sufficient to fulfill the requirements given by the claims that
     * are required.
     *
     * @param rs the required claims to check against
     * @param ticket the supplied claims to test
     * @return the result of the claims processing action
     */
    fun claimsAreSatisfied(rs: ResourceSet, ticket: PermissionTicket): ClaimProcessingResult
}
