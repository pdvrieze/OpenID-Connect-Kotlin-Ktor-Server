/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package org.mitre.openid.connect.service.impl.spring

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import org.mitre.openid.connect.model.ClientStat
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.StatsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.concurrent.TimeUnit

/**
 * @author jricher
 */
@Service
class SpringStatsService : StatsService {
    @Autowired
    private lateinit var approvedSiteService: ApprovedSiteService

    @Deprecated("Only for JPA")
    constructor()

    constructor(approvedSiteService: ApprovedSiteService) {
        this.approvedSiteService = approvedSiteService
    }

    // stats cache
    private var summaryCache = createSummaryCache()

    private fun createSummaryCache(): LoadingCache<Unit, Map<String, Int>> {
        return Caffeine.newBuilder().expireAfterWrite(10, TimeUnit.MINUTES)
            .build { computeSummaryStats() }
    }

    override val summaryStats: Map<String, Int>
        get() = summaryCache.get(Unit)

    // do the actual computation
    private fun computeSummaryStats(): Map<String, Int> {
        // get all approved sites
        val allSites = approvedSiteService.all ?: emptySet()

        // process to find number of unique users and sites
        val userIds: MutableSet<String?> = HashSet()
        val clientIds: MutableSet<String?> = HashSet()
        for (approvedSite in allSites) {
            userIds.add(approvedSite.userId)
            clientIds.add(approvedSite.clientId)
        }

        return mapOf(
            "approvalCount" to allSites.size,
            "userCount" to userIds.size,
            "clientCount" to clientIds.size,
        )
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.StatsService#countForClientId(java.lang.String)
	 */
    override fun getCountForClientId(clientId: String): ClientStat? {
        val approvedSites = approvedSiteService.getByClientId(clientId) ?: return null

        return ClientStat().apply {
            approvedSiteCount = approvedSites.size
        }
    }

    /**
     * Reset both stats caches on a trigger (before the timer runs out). Resets the timers.
     */
    override fun resetCache() {
        summaryCache = createSummaryCache()
    }
}
