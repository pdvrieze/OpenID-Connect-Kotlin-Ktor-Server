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

import kotlinx.serialization.encodeToString
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.json
import org.mitre.openid.connect.service.MITREidDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataService.Context
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

/**
 *
 * Data service to import and export MITREid 1.3 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_3 : MITREidDataService {
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
        return json.encodeToString(mapOf(THIS_VERSION to toSerialConfig()))
    }

    fun toSerialConfig(): MITREidDataService.ExtendedConfiguration12 {
        val newClients = clientRepository.allClients.map { MITREidDataService.ClientDetailsConfiguration(ClientDetailsEntity.from(it)) }
        return MITREidDataService.ExtendedConfiguration12(
            clients = newClients,
            grants = approvedSiteRepository.all?.map {
                val approvedAccessTokens =
                    tokenRepository.getAccessTokensForApprovedSite(it).mapTo(HashSet()) { it.id!! }
                ApprovedSite.SerialDelegate(it, approvedAccessTokens)
            } ?: emptyList(),
            whitelistedSites = wlSiteRepository.all?.toList() ?: emptyList(),
            blacklistedSites = blSiteRepository.all.toList(),
            authenticationHolders = authHolderRepository.all.map { AuthenticationHolderEntity.SerialDelegate12(it) },
            accessTokens = tokenRepository.allAccessTokens.map { OAuth2AccessTokenEntity.SerialDelegate(it) },
            refreshTokens = tokenRepository.allRefreshTokens.map { OAuth2RefreshTokenEntity.SerialDelegate(it) },
            systemScopes = sysScopeRepository.all.toList(),
        )
    }


    override fun importData(config: MITREidDataService.ExtendedConfiguration) {
        val context = Context(THIS_VERSION, clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        context.importData(config)
    }

    override fun importData(configJson: String) {
        val conf = json.decodeFromString<MITREidDataService.ExtendedConfiguration12>(configJson)
        importData(conf)
    }

    override fun importGrant(context: Context, delegate: ApprovedSite.SerialDelegate) {
        with(delegate) {
            whitelistedSiteId = whitelistedSiteId.warnIgnored("whitelistedSiteId")
        }
        super.importGrant(context, delegate)
    }

    override fun fixObjectReferences(context: Context) {
        logger.info("Fixing object references...")
        for ((oldRefreshTokenId, clientRef) in context.maps.refreshTokenToClientRefs) {
            val client = context.clientRepository.getClientByClientId(clientRef)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.client = client?.let(ClientDetailsEntity::from)
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for ((oldRefreshTokenId, oldAuthHolderId) in context.maps.refreshTokenToAuthHolderRefs) {
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId]!!
            val authHolder = context.authHolderRepository.getById(newAuthHolderId)!!
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.authenticationHolder = authHolder
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for ((oldAccessTokenId, clientRef) in context.maps.accessTokenToClientRefs) {
            val client = context.clientRepository.getClientByClientId(clientRef)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.client = client?.let(ClientDetailsEntity::from)
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldAuthHolderId) in context.maps.accessTokenToAuthHolderRefs) {
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId] ?: error("No autholder old->new for $oldAuthHolderId")
            val authHolder = context.authHolderRepository.getById(newAuthHolderId) ?: error("No authHolder with id $newAuthHolderId found")
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in context.maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId] ?: error("No refresh old->new for $oldRefreshTokenId")
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.setRefreshToken(refreshToken)
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldGrantId, oldAccessTokenIds) in context.maps.grantToAccessTokensRefs) {
            val newGrantId = context.maps.grantOldToNewIdMap[oldGrantId]!!
            val site = context.approvedSiteRepository.getById(newGrantId)!!

            for (oldTokenId in oldAccessTokenIds) {
                val newTokenId = context.maps.accessTokenOldToNewIdMap[oldTokenId] ?: error("No access old->new map for $oldTokenId")
                val token = context.tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                context.tokenRepository.saveAccessToken(token)
            }

            context.approvedSiteRepository.save(site)
        }
        /*
        refreshTokenToClientRefs.clear();
        refreshTokenToAuthHolderRefs.clear();
        accessTokenToClientRefs.clear();
        accessTokenToAuthHolderRefs.clear();
        accessTokenToRefreshTokenRefs.clear();
        refreshTokenOldToNewIdMap.clear();
        accessTokenOldToNewIdMap.clear();
        grantOldToNewIdMap.clear();
        */
        logger.info("Done fixing object references.")
    }

    companion object {
        private val logger = getLogger<MITREidDataService_1_3>()
        internal const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_3
    }
}
