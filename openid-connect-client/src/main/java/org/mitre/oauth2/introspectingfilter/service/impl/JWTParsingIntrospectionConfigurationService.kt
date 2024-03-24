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
/**
 *
 */
package org.mitre.oauth2.introspectingfilter.service.impl

import com.nimbusds.jwt.JWTParser
import org.mitre.oauth2.introspectingfilter.service.IntrospectionConfigurationService
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.client.service.ServerConfigurationService
import java.text.ParseException

/**
 *
 * Parses the incoming accesstoken as a JWT and determines the issuer based on
 * the "iss" field inside the JWT. Uses the ServerConfigurationService to determine
 * the introspection URL for that issuer.
 *
 * @author jricher
 */
class JWTParsingIntrospectionConfigurationService : IntrospectionConfigurationService {
    /**
     * @return the serverConfigurationService
     */
    /**
     * @param serverConfigurationService the serverConfigurationService to set
     */
    lateinit var serverConfigurationService: ServerConfigurationService
    private lateinit var clientConfigurationService: ClientConfigurationService

    /**
     * @param clientConfigurationService the clientConfigurationService to set
     */
    fun setClientConfigurationService(clientConfigurationService: ClientConfigurationService) {
        this.clientConfigurationService = clientConfigurationService
    }

    private fun getIssuer(accessToken: String): String? {
        try {
            val jwt = JWTParser.parse(accessToken)

            return jwt.jwtClaimsSet.issuer
        } catch (e: ParseException) {
            throw IllegalArgumentException("Unable to parse JWT", e)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.introspectingfilter.IntrospectionConfigurationService#getIntrospectionUrl(java.lang.String)
	 */
    override fun getIntrospectionUrl(accessToken: String): String {
        val issuer = getIssuer(accessToken)?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("No issuer claim found in JWT")

        val server = serverConfigurationService.getServerConfiguration(issuer)
            ?: throw IllegalArgumentException("Could not find server configuration for issuer $issuer")

        return server.introspectionEndpointUri?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("Server does not have Introspection Endpoint defined")
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.introspectingfilter.service.IntrospectionConfigurationService#getClientConfiguration(java.lang.String)
	 */
    override fun getClientConfiguration(accessToken: String): RegisteredClient {
        val issuer = getIssuer(accessToken)?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("No issuer claim found in JWT")

        val server = serverConfigurationService.getServerConfiguration(issuer)
            ?: throw IllegalArgumentException("Could not find server configuration for issuer $issuer")

        return clientConfigurationService.getClientConfiguration(server)
            ?: throw IllegalArgumentException("Could not find client configuration for issuer $issuer")
    }
}
