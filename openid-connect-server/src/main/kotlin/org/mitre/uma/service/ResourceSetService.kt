package org.mitre.uma.service

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.uma.model.ResourceSet

/**
 *
 * Manage registered resource sets at this authorization server.
 *
 * @author jricher
 */
interface ResourceSetService {
    fun saveNew(rs: ResourceSet): ResourceSet

    fun getById(id: Long): ResourceSet?

    fun update(oldRs: ResourceSet, newRs: ResourceSet): ResourceSet

    fun remove(rs: ResourceSet?)

    fun getAllForOwner(owner: String): Collection<ResourceSet>

    fun getAllForOwnerAndClient(owner: String, authClientId: String): Collection<ResourceSet>

    fun getAllForClient(client: OAuthClientDetails): Collection<ResourceSet>
}
