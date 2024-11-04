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

import io.github.pdvrieze.oidc.util.CoroutineCache
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.errors.*
import kotlinx.io.IOException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parseRegistered
import org.mitre.openid.connect.client.AuthenticationServiceException
import org.mitre.openid.connect.client.service.ClientConfigurationService
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.openid.connect.config.ServerConfiguration
import org.mitre.util.getLogger
import java.util.concurrent.ExecutionException

/**
 * @author jricher
 */
class DynamicRegistrationClientConfigurationService(
    private val httpClient: HttpClient = HttpClient(CIO)
) : ClientConfigurationService {

    private val clients = CoroutineCache(::loadImpl) {
        maximumSize(50)
    }

    var registeredClientService: RegisteredClientService = InMemoryRegisteredClientService()

    private var template: RegisteredClient? = null

    var whitelist: Set<String?> = HashSet()
    var blacklist: Set<String?> = HashSet()

    override suspend fun getClientConfiguration(issuer: ServerConfiguration): RegisteredClient? {
        try {
            if (!whitelist.isEmpty() && !whitelist.contains(issuer.issuer)) {
                throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: $issuer")
            }

            if (blacklist.contains(issuer.issuer)) {
                throw AuthenticationServiceException("Issuer was in blacklist: $issuer")
            }

            return clients.load(issuer)
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
        this.template = template?.copy(
            client = template.client.copy(
                clientId = null,
                clientSecret = null,
            ),
            registrationClientUri = null,
            registrationAccessToken = null,
        )
    }

    @Throws(Exception::class)
    suspend fun loadImpl(serverConfig: ServerConfiguration): RegisteredClient {


        val knownClient = registeredClientService.getByIssuer(serverConfig.issuer!!)
        if (knownClient == null) {
            // dynamically register this client

            val serializedClient = Json.encodeToString(template!!)

            val response = httpClient.post(serverConfig.registrationEndpointUri!!) {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)

                setBody(serializedClient)
            }
            if (! response.status.isSuccess()) {
                throw IOException("Error registering client ${response.status}")
            }

            val client = parseRegistered(response.bodyAsText())

            // save this client for later
            registeredClientService.save(serverConfig.issuer!!, client)

            return client
        } else {
            if (knownClient.clientId != null) {
                // it's got a client ID from the store, don't bother trying to load it
                return knownClient
            } else {
                // load this client's information from the server

                val resp = httpClient.get(knownClient.registrationClientUri!!) {
                    bearerAuth(knownClient.registrationAccessToken!!)
                    accept(ContentType.Application.Json)
                }
                if (!resp.status.isSuccess()) {
                    throw AuthenticationException("Error loading previously registered client information from server")
                }

                // TODO: handle HTTP errors

                return parseRegistered(resp.bodyAsText())
            }
        }
    }


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DynamicRegistrationClientConfigurationService>()
    }
}
