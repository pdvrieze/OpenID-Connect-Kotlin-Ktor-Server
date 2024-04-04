/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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

import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.util.requireId
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataService.Context
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

/**
 *
 * Data service to import and export MITREid 1.2 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_2 : MITREidDataService {
    @Autowired
    private lateinit var clientRepository: OAuth2ClientRepository

    @Autowired
    private lateinit var approvedSiteRepository: ApprovedSiteRepository

    @Autowired
    private lateinit var wlSiteRepository: WhitelistedSiteRepository

    @Autowired
    private lateinit var blSiteRepository: BlacklistedSiteRepository

    @Autowired
    private lateinit var authHolderRepository: AuthenticationHolderRepository

    @Autowired
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Autowired
    private lateinit var sysScopeRepository: SystemScopeRepository

    @Autowired(required = false)
    private val extensions = emptyList<MITREidDataServiceExtension>()

    private val maps = MITREidDataServiceMaps()

    override fun supportsVersion(version: String?): Boolean {
        return THIS_VERSION == version
    }

    override fun exportData(): String {
        throw UnsupportedOperationException("Can not export 1.2 format from this version.")
    }

    override fun importData(config: MITREidDataService.ExtendedConfiguration) {
        val context = Context(THIS_VERSION, clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        context.importData(config)
    }

    override fun importData(configJson: String) {
        importData(MITREidDataService.json.decodeFromString<MITREidDataService.ExtendedConfiguration12>(configJson))
    }

    override fun importClient(context: Context, client: MITREidDataService.ClientDetailsConfiguration) {
        with(client) {
            // New in 1.3
            codeChallengeMethod = codeChallengeMethod.warnIgnored("codeChallengeMethod")
            softwareId = softwareId.warnIgnored("softwareId")
            softwareVersion = softwareVersion.warnIgnored("softwareVersion")
            softwareStatement = softwareStatement.warnIgnored("softwareStatement")
            createdAt = createdAt.warnIgnored("createdAt")
        }

        super.importClient(context, client)
    }

    override fun importGrant(context: Context, delegate: ApprovedSite.SerialDelegate) {
        with(delegate) {
            whitelistedSiteId = whitelistedSiteId.warnIgnored("whitelistedSiteId")
        }
        super.importGrant(context, delegate)
    }

    override fun fixObjectReferences(context: Context) {
        logger.info("Fixing object references...")
        for (oldRefreshTokenId in context.maps.refreshTokenToClientRefs.keys) {
            val clientRef = context.maps.refreshTokenToClientRefs[oldRefreshTokenId]
            val client = context.clientRepository.getClientByClientId(clientRef!!)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.client = client
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for (oldRefreshTokenId in context.maps.refreshTokenToAuthHolderRefs.keys) {
            val oldAuthHolderId = context.maps.refreshTokenToAuthHolderRefs[oldRefreshTokenId]
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId]
            val authHolder = context.authHolderRepository.getById(newAuthHolderId)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.authenticationHolder = authHolder!!
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for (oldAccessTokenId in context.maps.accessTokenToClientRefs.keys) {
            val clientRef = context.maps.accessTokenToClientRefs[oldAccessTokenId]
            val client = context.clientRepository.getClientByClientId(clientRef!!)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.client = client
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for (oldAccessTokenId in context.maps.accessTokenToAuthHolderRefs.keys) {
            val oldAuthHolderId = context.maps.accessTokenToAuthHolderRefs[oldAccessTokenId]
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId] ?: error("Missing authHolder map $oldAuthHolderId")
            val authHolder = context.authHolderRepository.getById(newAuthHolderId) ?: error("Missing authHolder $newAuthHolderId")
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId].requireId()
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in context.maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId] ?: error("Missing map for old refresh token: $oldRefreshTokenId")
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.refreshToken = refreshToken
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for (oldGrantId in context.maps.grantToAccessTokensRefs.keys) {
            val oldAccessTokenIds = context.maps.grantToAccessTokensRefs[oldGrantId]!!

            val newGrantId = context.maps.grantOldToNewIdMap[oldGrantId]!!
            val site = context.approvedSiteRepository.getById(newGrantId)

            for (oldTokenId in oldAccessTokenIds) {
                val newTokenId = context.maps.accessTokenOldToNewIdMap[oldTokenId]?: error("Missing map $oldTokenId")
                val token = context.tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                context.tokenRepository.saveAccessToken(token)
            }

            context.approvedSiteRepository.save(site!!)
        }
        logger.info("Done fixing object references.")
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService_1_2::class.java)
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_2
    }
}
