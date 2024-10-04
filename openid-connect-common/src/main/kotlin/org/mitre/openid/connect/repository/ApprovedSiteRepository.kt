package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.ApprovedSite

/**
 * ApprovedSite repository interface
 *
 * @author Michael Joseph Walsh, aanganes
 */
interface ApprovedSiteRepository {
    /**
     * Returns the ApprovedSite for the given id
     *
     * @param id The id of the ApprovedSite
     * @return a valid ApprovedSite if it exists, null otherwise
     */
    fun getById(id: Long): ApprovedSite?

    /**
     * Return a collection of all ApprovedSites managed by this repository
     *
     * @return the ApprovedSite collection, or null
     */
    val all: Collection<ApprovedSite>

    /**
     * Return a collection of ApprovedSite managed by this repository matching the
     * provided client ID and user ID
     *
     */
    fun getByClientIdAndUserId(clientId: String, userId: String): Collection<ApprovedSite>

    /**
     * Removes the given ApprovedSite from the repository
     *
     * the ApprovedSite object to remove
     */
    fun remove(approvedSite: ApprovedSite)

    /**
     * Persists an ApprovedSite
     *
     * valid ApprovedSite instance
     * @return the persisted entity
     */
    fun save(approvedSite: ApprovedSite): ApprovedSite

    /**
     * Get all sites approved by this user
     */
    fun getByUserId(userId: String): Collection<ApprovedSite>

    /**
     * Get all sites associated with this client
     */
    fun getByClientId(clientId: String): Collection<ApprovedSite>
}
