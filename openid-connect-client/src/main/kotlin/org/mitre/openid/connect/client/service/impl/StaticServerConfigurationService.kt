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
import javax.annotation.PostConstruct

/**
 * Statically configured server configuration service that maps issuer URLs to server configurations to use at that issuer.
 *
 * @author jricher
 */
class StaticServerConfigurationService : ServerConfigurationService {
    // map of issuer url -> server configuration information
    lateinit var servers: Map<String, ServerConfiguration>

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.ServerConfigurationService#getServerConfiguration(java.lang.String)
	 */
    override fun getServerConfiguration(issuer: String): ServerConfiguration? {
//        if (!::servers.isInitialized) return null
        return servers[issuer]
    }

    @PostConstruct
    fun afterPropertiesSet() {
        require(::servers.isInitialized && servers.isNotEmpty()) { "Servers map cannot be null or empty." }
    }
}