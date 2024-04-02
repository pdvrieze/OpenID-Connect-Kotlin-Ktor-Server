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

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.google.gson.Gson
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parseRegistered
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.openid.connect.config.ServerConfiguration
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import java.util.concurrent.ExecutionException

/**
 * @author jricher
 */
class DynamicRegistrationClientConfigurationService(
    httpClient: HttpClient? = HttpClientBuilder.create().useSystemProperties().build()
) : ClientConfigurationService {
    private val clients: LoadingCache<ServerConfiguration, RegisteredClient?> =
        CacheBuilder.newBuilder().build(DynamicClientRegistrationLoader(httpClient))

    var registeredClientService: RegisteredClientService = InMemoryRegisteredClientService()

    private var template: RegisteredClient? = null

    var whitelist: Set<String?> = HashSet()
    var blacklist: Set<String?> = HashSet()

    override fun getClientConfiguration(issuer: ServerConfiguration): RegisteredClient? {
        try {
            if (!whitelist.isEmpty() && !whitelist.contains(issuer.issuer)) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $issuer")
            }

            if (blacklist.contains(issuer.issuer)) {
                throw AuthenticationServiceException("Issuer was in blacklist: $issuer")
            }

            return clients[issuer]
        } catch (e: UncheckedExecutionException) {
            logger.warn("Unable to get client configuration", e)
            return null
        } catch (e: ExecutionException) {
            logger.warn("Unable to get client configuration", e)
            return null
        }
    }

    fun getTemplate(): RegisteredClient? {
        return template
    }

    fun setTemplate(template: RegisteredClient?) {
        // make sure the template doesn't have unwanted fields set on it
        template?.apply {
            clientId = null
            clientSecret = null
            registrationClientUri = null
            registrationAccessToken = null
        }

        this.template = template
    }


    /**
     * Loader class that fetches the client information.
     *
     * If a client has been registered (ie, it's known to the RegisteredClientService), then this
     * will fetch the client's configuration from the server.
     *
     * @author jricher
     */
    inner class DynamicClientRegistrationLoader(
        httpClient: HttpClient? = HttpClientBuilder.create().useSystemProperties().build()
    ) : CacheLoader<ServerConfiguration, RegisteredClient?>() {
        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
        private val gson = Gson() // note that this doesn't serialize nulls by default

        @Throws(Exception::class)
        override fun load(serverConfig: ServerConfiguration): RegisteredClient? {
            val restTemplate = RestTemplate(httpFactory)


            val knownClient = registeredClientService.getByIssuer(serverConfig.issuer!!)
            if (knownClient == null) {
                // dynamically register this client

                val serializedClient = Json.encodeToString(template!!)

                val headers = HttpHeaders()
                headers.contentType = MediaType.APPLICATION_JSON
                headers.accept = listOf(MediaType.APPLICATION_JSON)

                val entity = HttpEntity(serializedClient, headers)

                try {
                    val registered =
                        restTemplate.postForObject(serverConfig.registrationEndpointUri, entity, String::class.java)

                    val client = parseRegistered(registered)

                    // save this client for later
                    registeredClientService.save(serverConfig.issuer!!, client!!)

                    return client
                } catch (rce: RestClientException) {
                    throw InvalidClientException("Error registering client with server")
                }
            } else {
                if (knownClient.clientId != null) {
                    // it's got a client ID from the store, don't bother trying to load it
                    return knownClient
                } else {
                    // load this client's information from the server

                    val headers = HttpHeaders()
                    headers["Authorization"] =
                        String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, knownClient.registrationAccessToken)
                    headers.accept = listOf(MediaType.APPLICATION_JSON)

                    val entity = HttpEntity<String>(headers)

                    try {
                        val registered =
                            restTemplate.exchange(knownClient.registrationClientUri, HttpMethod.GET, entity, String::class.java).body

                        // TODO: handle HTTP errors
                        val client = parseRegistered(registered)

                        return client
                    } catch (rce: RestClientException) {
                        throw InvalidClientException("Error loading previously registered client information from server")
                    }
                }
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DynamicRegistrationClientConfigurationService::class.java)
    }
}
