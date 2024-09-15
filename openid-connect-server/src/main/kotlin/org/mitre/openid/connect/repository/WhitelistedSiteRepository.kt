package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.WhitelistedSite

/**
 * WhitelistedSite repository interface
 *
 * @author Michael Joseph Walsh, aanganes
 */
interface WhitelistedSiteRepository {
    /**
     * Return a collection of all WhitelistedSite managed by this repository
     *
     * @return the WhitelistedSite collection, or null
     */
    val all: Collection<WhitelistedSite>

    /**
     * Returns the WhitelistedSite for the given id
     *
     * id the id of the WhitelistedSite
     * @return a valid WhitelistedSite if it exists, null otherwise
     */
    fun getById(id: Long): WhitelistedSite?

    /**
     * Find a WhitelistedSite by its associated ClientDetails reference
     *
     * @param client    the Relying Party
     * @return            the corresponding WhitelistedSite if one exists for the RP, or null
     */
    fun getByClientId(clientId: String): WhitelistedSite?

    /**
     * Return a collection of the WhitelistedSites created by a given user
     *
     * @param creator    the id of the admin who may have created some WhitelistedSites
     * @return            the collection of corresponding WhitelistedSites, if any, or null
     */
    fun getByCreator(creatorId: String): Collection<WhitelistedSite>

    /**
     * Removes the given IdToken from the repository
     *
     * the WhitelistedSite object to remove
     */
    fun remove(whitelistedSite: WhitelistedSite)

    /**
     * Persists a WhitelistedSite
     *
     */
    fun save(whiteListedSite: WhitelistedSite): WhitelistedSite

    /**
     * Persist changes to a whitelistedSite. The ID of oldWhitelistedSite is retained.
     */
    fun update(oldWhitelistedSite: WhitelistedSite, whitelistedSite: WhitelistedSite): WhitelistedSite
}
