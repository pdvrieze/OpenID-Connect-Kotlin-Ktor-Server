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

import org.mitre.openid.connect.client.service.ServerConfigurationService
import org.mitre.openid.connect.config.ServerConfiguration

/**
 * Houses both a static server configuration and a dynamic server configuration
 * service in one object. Checks the static service first, then falls through to
 * the dynamic service.
 *
 * Provides configuration passthrough to the dynamic service's whitelist and blacklist,
 * and to the static service's server map.
 *
 *
 * @author jricher
 */
class HybridServerConfigurationService(
    private val staticServerService: StaticServerConfigurationService,
    private val dynamicServerService: DynamicServerConfigurationService
) : ServerConfigurationService {

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.ServerConfigurationService#getServerConfiguration(java.lang.String)
	 */
    override fun getServerConfiguration(issuer: String): ServerConfiguration? {
        val server = staticServerService.getServerConfiguration(issuer)
        return server ?: dynamicServerService.getServerConfiguration(issuer)
    }


    val servers: Map<String, ServerConfiguration>
        /**
         * @see org.mitre.openid.connect.client.service.impl.StaticServerConfigurationService.getServers
         */
        get() = staticServerService.servers


//    fun setServers(servers: Map<String, ServerConfiguration>) {
//        staticServerService.servers = servers
//    }


    var whitelist: Set<String?>?
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService.getWhitelist
         */
        get() = dynamicServerService.whitelist
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService.setWhitelist
         */
        set(whitelist) {
            dynamicServerService.whitelist = whitelist!!
        }


    var blacklist: Set<String?>
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService.getBlacklist
         */
        get() = dynamicServerService.blacklist
        /**
         * @see org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService.setBlacklist
         */
        set(blacklist) {
            dynamicServerService.blacklist = blacklist
        }
}
