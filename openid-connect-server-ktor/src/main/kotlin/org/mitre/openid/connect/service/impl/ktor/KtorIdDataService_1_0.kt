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

import org.mitre.oauth2.model.AuthenticationHolder
import org.mitre.oauth2.model.request.InternalForStorage
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.DataServiceContext
import org.mitre.openid.connect.service.KtorIdDataService
import org.mitre.openid.connect.service.KtorIdDataService.*
import org.mitre.openid.connect.service.KtorIdDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.getLogger

/**
 *
 * Data service to import MITREid 1.0 configuration.
 *
 * @author jricher
 * @author arielak
 */
class KtorIdDataService_1_0(
    private val clientRepository: OAuth2ClientRepository,
    private val approvedSiteRepository: ApprovedSiteRepository,
    private val wlSiteRepository: WhitelistedSiteRepository,
    private val blSiteRepository: BlacklistedSiteRepository,
    private val authHolderRepository: AuthenticationHolderRepository,
    private val tokenRepository: OAuth2TokenRepository,
    private val sysScopeRepository: SystemScopeRepository,
    private var extensions: List<MITREidDataServiceExtension> = emptyList(),
) : KtorIdDataService {

    private val maps: MITREidDataServiceMaps = MITREidDataServiceMaps()

    override fun supportsVersion(version: String?): Boolean {
        return THIS_VERSION == version
    }

    override fun exportData(): String {
        throw UnsupportedOperationException("Can not export 1.0 format from this version.")
    }

    override fun importData(config: ExtendedConfiguration) {
        val context = DataServiceContext(THIS_VERSION, clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        context.importData(config)
    }

    override fun importData(configJson: String) {
        importData(KtorIdDataService.json.decodeFromString<ExtendedConfiguration10>(configJson))
    }

    override fun importClient(context: DataServiceContext, client: ClientDetailsConfiguration) {
        with(client) {
            // New in 1.2
            claimsRedirectUris = claimsRedirectUris.warnIgnored("claimsRedirectUris")
            jwks = jwks.warnIgnored("jwks")
            isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh.warnIgnored("isClearAccessTokensOnRefresh", true)

            // New in 1.3
            codeChallengeMethod = codeChallengeMethod.warnIgnored("codeChallengeMethod")
            softwareId = softwareId.warnIgnored("softwareId")
            softwareVersion = softwareVersion.warnIgnored("softwareVersion")
            softwareStatement = softwareStatement.warnIgnored("softwareStatement")
            createdAt = createdAt.warnIgnored("createdAt")
        }

        super.importClient(context, client)
    }

    @OptIn(InternalForStorage::class)
    override fun importAuthenticationHolder(context: DataServiceContext, ahe: AuthenticationHolder) {
        val r = ahe.authorizationRequest
        r.authHolderExtensions.warnIgnored("authentication/userAuthentication/extensions")

        super.importAuthenticationHolder(context, ahe)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<KtorIdDataService_1_0>()
        private const val THIS_VERSION = KtorIdDataService.MITREID_CONNECT_1_0
    }
}
