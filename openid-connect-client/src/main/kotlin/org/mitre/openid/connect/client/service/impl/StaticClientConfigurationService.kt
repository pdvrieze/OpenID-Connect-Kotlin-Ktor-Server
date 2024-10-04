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
package org.mitre.openid.connect.client.service.impl

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.config.ServerConfiguration

/**
 * Client configuration service that holds a static map from issuer URL to a ClientDetails object to use at that issuer.
 *
 * Designed to be configured as a bean.
 *
 * @author jricher
 */
class StaticClientConfigurationService(val clients: Map<String?, RegisteredClient>) : ClientConfigurationService {
    // Map of issuer URL -> client configuration information

    init {
        require(clients.isNotEmpty()) {
            "Clients map cannot be null or empty"
        }
    }


    /**
     * Get the client configured for this issuer
     *
     * @see org.mitre.openid.connect.client.service.ClientConfigurationService.getClientConfiguration
     */
    override suspend fun getClientConfiguration(issuer: ServerConfiguration): RegisteredClient? {
        return clients[issuer.issuer]
    }
}
