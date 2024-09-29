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
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.openid.connect.config.ServerConfiguration

/**
 * Houses both a static client configuration and a dynamic client configuration
 * service in one object. Checks the static service first, then falls through to
 * the dynamic service.
 *
 * Provides configuration passthrough for the template, registered client service, whitelist,
 * and blacklist for the dynamic service, and to the static service's client map.
 *
 * @author jricher
 */
class HybridClientConfigurationService(
    private var staticClientService: StaticClientConfigurationService,
    private var dynamicClientService: DynamicRegistrationClientConfigurationService,
) : ClientConfigurationService {

    override fun getClientConfiguration(issuer: ServerConfiguration): RegisteredClient? {
        val client = staticClientService.getClientConfiguration(issuer)
        return client ?: dynamicClientService.getClientConfiguration(issuer)
    }

    val clients: Map<String?, RegisteredClient>
        get() = staticClientService.clients
//        set(clients) {
//            staticClientService.clients = clients
//        }

    var template: RegisteredClient?
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.getTemplate
         */
        get() = dynamicClientService.getTemplate()
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.setTemplate
         */
        set(template) {
            dynamicClientService.setTemplate(template)
        }

    var registeredClientService: RegisteredClientService?
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.getRegisteredClientService
         */
        get() = dynamicClientService.registeredClientService
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.setRegisteredClientService
         */
        set(registeredClientService) {
            dynamicClientService.registeredClientService = registeredClientService!!
        }

    var whitelist: Set<String?>?
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.getWhitelist
         */
        get() = dynamicClientService.whitelist
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.setWhitelist
         */
        set(whitelist) {
            dynamicClientService.whitelist = whitelist!!
        }

    var blacklist: Set<String?>?
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.getBlacklist
         */
        get() = dynamicClientService.blacklist
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicRegistrationClientConfigurationService.setBlacklist
         */
        set(blacklist) {
            dynamicClientService.blacklist = blacklist!!
        }
}
