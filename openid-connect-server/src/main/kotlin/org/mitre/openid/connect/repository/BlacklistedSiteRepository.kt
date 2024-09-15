package org.mitre.openid.connect.repository

import org.mitre.openid.connect.model.BlacklistedSite

/**
 * @author jricher
 */
interface BlacklistedSiteRepository {
    val all: Collection<BlacklistedSite>

    fun getById(id: Long): BlacklistedSite?

    fun remove(blacklistedSite: BlacklistedSite)

    fun save(blacklistedSite: BlacklistedSite): BlacklistedSite

    fun update(oldBlacklistedSite: BlacklistedSite, blacklistedSite: BlacklistedSite): BlacklistedSite
}
