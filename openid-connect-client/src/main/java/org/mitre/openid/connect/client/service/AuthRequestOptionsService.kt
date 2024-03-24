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
package org.mitre.openid.connect.client.service

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.config.ServerConfiguration
import javax.servlet.http.HttpServletRequest

/**
 *
 * This service provides any extra options that need to be passed to the authentication request,
 * either through the authorization endpoint (getOptions) or the token endpoint (getTokenOptions).
 * These options may depend on the server configuration, client configuration, or HTTP request.
 *
 * @author jricher
 */
interface AuthRequestOptionsService {
    /**
     * The set of options needed at the authorization endpoint.
     */
    fun getOptions(
        server: ServerConfiguration,
        client: RegisteredClient,
        request: HttpServletRequest
    ): Map<String, String>

    /**
     * The set of options needed at the token endpoint.
     */
    fun getTokenOptions(
        server: ServerConfiguration,
        client: RegisteredClient,
        request: HttpServletRequest
    ): Map<String, String>
}
