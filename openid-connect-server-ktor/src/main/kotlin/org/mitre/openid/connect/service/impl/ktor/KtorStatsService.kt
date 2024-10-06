package org.mitre.openid.connect.service.impl.ktor

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import org.mitre.openid.connect.model.ClientStat
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.StatsService
import java.util.concurrent.TimeUnit

/**
 * @author jricher
 */
class KtorStatsService(
    private val approvedSiteService: ApprovedSiteService
) : StatsService {

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
