package org.mitre.uma.repository

import org.mitre.uma.model.ResourceSet

/**
 * @author jricher
 */
interface ResourceSetRepository {
    fun save(rs: ResourceSet): ResourceSet

    fun getById(id: Long): ResourceSet?

    fun remove(rs: ResourceSet)

    fun getAllForOwner(owner: String): Collection<ResourceSet>

    fun getAllForOwnerAndClient(owner: String, clientId: String): Collection<ResourceSet>

    val all: Collection<ResourceSet>

    fun getAllForClient(clientId: String): Collection<ResourceSet>
}
