package org.mitre.uma.service

import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.Policy

/**
 * Service to create special tokens for UMA.
 *
 * @author jricher
 */
interface UmaTokenService {
    /**
     * Create the RPT from the given authentication and ticket.
     */
    fun createRequestingPartyToken(
        o2auth: AuthenticatedAuthorizationRequest,
        ticket: PermissionTicket,
        policy: Policy
    ): org.mitre.oauth2.model.OAuth2AccessTokenEntity
}
