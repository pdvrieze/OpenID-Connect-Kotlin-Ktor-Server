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

import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.DataServiceContext
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.*
import org.mitre.openid.connect.service.MITREidDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

/**
 *
 * Data service to import MITREid 1.0 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_0 : MITREidDataService {
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
    private var extensions: List<MITREidDataServiceExtension> = emptyList<MITREidDataServiceExtension>()

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
        importData(MITREidDataService.json.decodeFromString<ExtendedConfiguration10>(configJson))
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

    override fun importAuthenticationHolder(context: DataServiceContext, ahe: AuthenticationHolderEntity) {
        val r = ahe.authentication.authorizationRequest
        r.extensions.warnIgnored("authentication/userAuthentication/extensions")

        super.importAuthenticationHolder(context, ahe)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<MITREidDataService_1_0>()
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_0
    }
}
