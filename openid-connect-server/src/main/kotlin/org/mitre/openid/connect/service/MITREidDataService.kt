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
package org.mitre.openid.connect.service

import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository

class DataServiceContext(
    val version: String,
    val clientRepository: OAuth2ClientRepository,
    val approvedSiteRepository: ApprovedSiteRepository,
    val wlSiteRepository: WhitelistedSiteRepository,
    val blSiteRepository: BlacklistedSiteRepository,
    val authHolderRepository: AuthenticationHolderRepository,
    val tokenRepository: OAuth2TokenRepository,
    val sysScopeRepository: SystemScopeRepository,
    val extensions: List<MITREidDataServiceExtension>,
    val maps: MITREidDataServiceMaps,
)
