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
package org.mitre.openid.connect.service.impl

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.StatsService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*

/**
 * Implementation of the ApprovedSiteService
 *
 * @author Michael Joseph Walsh, aanganes
 */
@Service("defaultApprovedSiteService")
class DefaultApprovedSiteService : ApprovedSiteService {
    @Autowired
    private lateinit var approvedSiteRepository: ApprovedSiteRepository

    @Autowired
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Autowired
    private lateinit var statsService: StatsService

    override val all: Collection<ApprovedSite>?
        get() = approvedSiteRepository.all

    @Transactional(value = "defaultTransactionManager")
    override fun save(approvedSite: ApprovedSite): ApprovedSite {
        val a = approvedSiteRepository.save(approvedSite)
        statsService.resetCache()
        return a
    }

    override fun getById(id: Long): ApprovedSite? {
        return approvedSiteRepository.getById(id)
    }

    @Transactional(value = "defaultTransactionManager")
    override fun remove(approvedSite: ApprovedSite) {
        //Remove any associated access and refresh tokens

        val accessTokens = getApprovedAccessTokens(approvedSite)

        for (token in accessTokens) {
            if (token.refreshToken != null) {
                tokenRepository.removeRefreshToken(token.refreshToken!!)
            }
            tokenRepository.removeAccessToken(token)
        }

        approvedSiteRepository.remove(approvedSite)

        statsService.resetCache()
    }

    @Transactional(value = "defaultTransactionManager")
    override fun createApprovedSite(
        clientId: String?,
        userId: String?,
        timeoutDate: Date?,
        allowedScopes: Set<String>?
    ): ApprovedSite {
        val now = Date()
        val approvedSite = approvedSiteRepository.save(ApprovedSite())

        approvedSite.creationDate = now
        approvedSite.accessDate = now
        approvedSite.clientId = clientId
        approvedSite.userId = userId
        approvedSite.timeoutDate = timeoutDate
        approvedSite.allowedScopes = allowedScopes

        return save(approvedSite)
    }

    override fun getByClientIdAndUserId(clientId: String?, userId: String?): Collection<ApprovedSite>? {
        return approvedSiteRepository.getByClientIdAndUserId(clientId, userId)
    }

    /**
     * @see org.mitre.openid.connect.repository.ApprovedSiteRepository.getByUserId
     */
    override fun getByUserId(userId: String): Collection<ApprovedSite>? {
        return approvedSiteRepository.getByUserId(userId)
    }

    /**
     * @see org.mitre.openid.connect.repository.ApprovedSiteRepository.getByClientId
     */
    override fun getByClientId(clientId: String): Collection<ApprovedSite>? {
        return approvedSiteRepository.getByClientId(clientId)
    }


    override fun clearApprovedSitesForClient(client: ClientDetails) {
        val approvedSites = approvedSiteRepository.getByClientId(client.clientId)
        if (approvedSites != null) {
            for (approvedSite in approvedSites) {
                remove(approvedSite)
            }
        }
    }

    override fun clearExpiredSites() {
        logger.debug("Clearing expired approved sites")

        val expiredSites: Collection<ApprovedSite>? = expired
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
        get() = approvedSiteRepository.all?.filter(expired_predicate)

    override fun getApprovedAccessTokens(
        approvedSite: ApprovedSite
    ): List<OAuth2AccessTokenEntity> {
        return tokenRepository.getAccessTokensForApprovedSite(approvedSite)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DefaultApprovedSiteService::class.java)
    }
}
