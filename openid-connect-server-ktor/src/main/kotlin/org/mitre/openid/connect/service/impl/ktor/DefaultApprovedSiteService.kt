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
package org.mitre.openid.connect.service.impl.ktor

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.StatsService
import org.mitre.util.getLogger
import java.util.*

/**
 * Implementation of the ApprovedSiteService
 *
 * @author Michael Joseph Walsh, aanganes
 */
class DefaultApprovedSiteService(
    private var approvedSiteRepository: ApprovedSiteRepository,
    private var tokenRepository: OAuth2TokenRepository,
    statsService: StatsService? = null,
) : ApprovedSiteService {

    private var statsService: StatsService = statsService?: KtorStatsService(this)

    fun getStatsService(): StatsService = statsService

    override val all: Collection<ApprovedSite>
        get() = approvedSiteRepository.all

    override fun save(approvedSite: ApprovedSite): ApprovedSite {
        val a = approvedSiteRepository.save(approvedSite)
        statsService.resetCache()
        return a
    }

    override fun getById(id: Long): ApprovedSite? {
        return approvedSiteRepository.getById(id)
    }

    override fun remove(approvedSite: ApprovedSite) {
        //Remove any associated access and refresh tokens

        val accessTokens = getApprovedAccessTokens(approvedSite)

        for (token in accessTokens) {
            token.refreshToken?.let { tokenRepository.removeRefreshToken(it) }

            tokenRepository.removeAccessToken(token)
        }

        approvedSiteRepository.remove(approvedSite)

        statsService.resetCache()
    }

    override fun createApprovedSite(
        clientId: String?,
        userId: String?,
        timeoutDate: Date?,
        allowedScopes: Set<String>?
    ): ApprovedSite {
        val now = Date()
        val approvedSite = approvedSiteRepository.save(ApprovedSite(
            creationDate = now,
            accessDate = now,
            clientId = clientId,
            userId = userId,
            timeoutDate = timeoutDate,
            allowedScopes = allowedScopes ?: emptySet(),
        ))

        return save(approvedSite)
    }

    override fun getByClientIdAndUserId(clientId: String, userId: String): Collection<ApprovedSite> {
        return approvedSiteRepository.getByClientIdAndUserId(clientId, userId)
    }

    /**
     * @see org.mitre.openid.connect.repository.ApprovedSiteRepository.getByUserId
     */
    override fun getByUserId(userId: String): Collection<ApprovedSite> {
        return approvedSiteRepository.getByUserId(userId)
    }

    /**
     * @see org.mitre.openid.connect.repository.ApprovedSiteRepository.getByClientId
     */
    override fun getByClientId(clientId: String): Collection<ApprovedSite> {
        return approvedSiteRepository.getByClientId(clientId)
    }


    override fun clearApprovedSitesForClient(client: OAuthClientDetails) {
        val approvedSites = approvedSiteRepository.getByClientId(client.clientId)
        if (approvedSites != null) {
            for (approvedSite in approvedSites) {
                remove(approvedSite)
            }
        }
    }

    override fun clearExpiredSites() {
        logger.debug("Clearing expired approved sites")

        val expiredSites: Collection<ApprovedSite> = expired
        if (expiredSites != null) {
            if (expiredSites.isNotEmpty()) {
                logger.info("Found ${expiredSites.size} expired approved sites.")
            }
            for (expired in expiredSites) {
                remove(expired)
            }
        }
    }

    private val expired_predicate: (ApprovedSite?) -> Boolean = { input -> input != null && input.isExpired }
    private val expired
        get() = approvedSiteRepository.all.filter(expired_predicate)

    override fun getApprovedAccessTokens(
        approvedSite: ApprovedSite
    ): List<OAuth2AccessTokenEntity> {
        return tokenRepository.getAccessTokensForApprovedSite(approvedSite)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DefaultApprovedSiteService>()
    }
}
