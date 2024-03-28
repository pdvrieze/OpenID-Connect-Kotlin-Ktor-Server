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
import org.mitre.openid.connect.client.service.AuthRequestOptionsService
import org.mitre.openid.connect.config.ServerConfiguration
import javax.servlet.http.HttpServletRequest

/**
 *
 * Always returns the same set of options.
 *
 * @author jricher
 */
class StaticAuthRequestOptionsService : AuthRequestOptionsService {
    private var _options: MutableMap<String, String> = HashMap()
    var tokenOptions: Map<String, String> = HashMap()


    /**
     * @return the options object directly
     */
    var options: Map<String, String>
        get() = _options
        set(value) {
            this._options = value.toMutableMap()
        }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.AuthRequestOptionsService#getOptions(org.mitre.openid.connect.config.ServerConfiguration, org.mitre.oauth2.model.RegisteredClient, javax.servlet.http.HttpServletRequest)
	 */
    override fun getOptions(
        server: ServerConfiguration,
        client: RegisteredClient,
        request: HttpServletRequest
    ): MutableMap<String, String> {
        return _options
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.AuthRequestOptionsService#getTokenOptions(org.mitre.openid.connect.config.ServerConfiguration, org.mitre.oauth2.model.RegisteredClient, javax.servlet.http.HttpServletRequest)
	 */
    override fun getTokenOptions(
        server: ServerConfiguration,
        client: RegisteredClient,
        request: HttpServletRequest
    ): Map<String, String> {
        return tokenOptions
    }
}
