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
package org.mitre.oauth2.service.impl

import com.google.common.base.Strings
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.google.gson.JsonParser
import org.apache.commons.codec.binary.Base64
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.util.toJavaId
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.uma.service.ResourceSetService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import org.springframework.web.util.UriComponentsBuilder
import java.lang.Long
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

@Service
class DefaultOAuth2ClientDetailsEntityService : ClientDetailsEntityService {
    @Autowired
    private lateinit var clientRepository: OAuth2ClientRepository

    @Autowired
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Autowired
    private lateinit var approvedSiteService: ApprovedSiteService

    @Autowired
    private lateinit var whitelistedSiteService: WhitelistedSiteService

    @Autowired
    private lateinit var blacklistedSiteService: BlacklistedSiteService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Autowired
    private lateinit var statsService: StatsService

    @Autowired
    private lateinit var resourceSetService: ResourceSetService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    // map of sector URI -> list of redirect URIs
    private val sectorRedirects: LoadingCache<String, List<String>> = CacheBuilder.newBuilder()
        .expireAfterAccess(1, TimeUnit.HOURS)
        .maximumSize(100)
        .build(SectorIdentifierLoader(HttpClientBuilder.create().useSystemProperties().build()))

    override fun saveNewClient(client: ClientDetailsEntity): ClientDetailsEntity? {
        var client = client
        require(client.id == null) {  // if it's not null, it's already been saved, this is an error
            "Tried to save a new client with an existing ID: " + client.id
        }

        val registeredRedirectUri = client.registeredRedirectUri
        if (registeredRedirectUri != null) {
            for (uri in registeredRedirectUri) {
                require(!blacklistedSiteService.isBlacklisted(uri)) { "Client URI is blacklisted: $uri" }
            }
        }

        // assign a random clientid if it's empty
        // NOTE: don't assign a random client secret without asking, since public clients have no secret
        if (Strings.isNullOrEmpty(client.clientId)) {
            client = generateClientId(client)
        }

        // make sure that clients with the "refresh_token" grant type have the "offline_access" scope, and vice versa
        ensureRefreshTokenConsistency(client)

        // make sure we don't have both a JWKS and a JWKS URI
        ensureKeyConsistency(client)

        // check consistency when using HEART mode
        checkHeartMode(client)

        // timestamp this to right now
        client.createdAt = Date()


        // check the sector URI
        checkSectorIdentifierUri(client)


        ensureNoReservedScopes(client)

        val c = clientRepository.saveClient(client)

        statsService.resetCache()

        return c
    }

    /**
     * Make sure the client has only one type of key registered
     */
    private fun ensureKeyConsistency(client: ClientDetailsEntity?) {
        require(!(client!!.jwksUri != null && client.jwks != null)) {
            // a client can only have one key type or the other, not both
            "A client cannot have both JWKS URI and JWKS value"
        }
    }

    /**
     * Make sure the client doesn't request any system reserved scopes
     */
    private fun ensureNoReservedScopes(client: ClientDetailsEntity) {
        // make sure a client doesn't get any special system scopes
        var requestedScope: Set<SystemScope>? = scopeService.fromStrings(client.scope)

        if (requestedScope!=null) {
            requestedScope = scopeService.removeReservedScopes(requestedScope)
        }

        client.setScope(scopeService.toStrings(requestedScope))
    }

    /**
     * Load the sector identifier URI if it exists and check the redirect URIs against it
     */
    private fun checkSectorIdentifierUri(client: ClientDetailsEntity?) {
        if (!Strings.isNullOrEmpty(client!!.sectorIdentifierUri)) {
            try {
                val redirects = sectorRedirects[client.sectorIdentifierUri]

                val registeredRedirectUri = client.registeredRedirectUri
                if (registeredRedirectUri != null) {
                    for (uri in registeredRedirectUri) {
                        require(redirects.contains(uri)) { "Requested Redirect URI $uri is not listed at sector identifier $redirects" }
                    }
                }
            } catch (e: UncheckedExecutionException) {
                throw IllegalArgumentException("Unable to load sector identifier URI ${client.sectorIdentifierUri}: ${e.message}")
            } catch (e: ExecutionException) {
                throw IllegalArgumentException("Unable to load sector identifier URI ${client.sectorIdentifierUri}: ${e.message}")
            }
        }
    }

    /**
     * Make sure the client has the appropriate scope and grant type.
     */
    private fun ensureRefreshTokenConsistency(client: ClientDetailsEntity) {
        if (client.authorizedGrantTypes.contains("refresh_token")
            || client.scope.contains(SystemScopeService.OFFLINE_ACCESS)
        ) {
            client.scope.add(SystemScopeService.OFFLINE_ACCESS)
            client.authorizedGrantTypes.add("refresh_token")
        }
    }

    /**
     * If HEART mode is enabled, make sure the client meets the requirements:
     * - Only one of authorization_code, implicit, or client_credentials can be used at a time
     * - A redirect_uri must be registered with either authorization_code or implicit
     * - A key must be registered
     * - A client secret must not be generated
     * - authorization_code and client_credentials must use the private_key authorization method
     */
    private fun checkHeartMode(client: ClientDetailsEntity?) {
        if (config.isHeartMode) {
            if (client!!.grantTypes.contains("authorization_code")) {
                // make sure we don't have incompatible grant types
                require(!(client.grantTypes.contains("implicit") || client.grantTypes.contains("client_credentials"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.PRIVATE_KEY)) { "[HEART mode] Authorization code clients must use the private_key authentication method" }

                // make sure we've got a redirect URI
                require(!client.redirectUris.isEmpty()) { "[HEART mode] Authorization code clients must register at least one redirect URI" }
            }

            if (client.grantTypes.contains("implicit")) {
                // make sure we don't have incompatible grant types
                require(!(client.grantTypes.contains("authorization_code") || client.grantTypes.contains("client_credentials") || client.grantTypes.contains("refresh_token"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.NONE)) { "[HEART mode] Implicit clients must use the none authentication method" }

                // make sure we've got a redirect URI
                require(!client.redirectUris.isEmpty()) { "[HEART mode] Implicit clients must register at least one redirect URI" }
            }

            if (client.grantTypes.contains("client_credentials")) {
                // make sure we don't have incompatible grant types
                require(!(client.grantTypes.contains("authorization_code") || client.grantTypes.contains("implicit") || client.grantTypes.contains("refresh_token"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.PRIVATE_KEY)) { "[HEART mode] Client credentials clients must use the private_key authentication method" }

                // make sure we've got a redirect URI
                require(client.redirectUris.isEmpty()) { "[HEART mode] Client credentials clients must not register a redirect URI" }
            }

            require(!client.grantTypes.contains("password")) { "[HEART mode] Password grant type is forbidden" }

            // make sure we don't have a client secret
            require(Strings.isNullOrEmpty(client.clientSecret)) { "[HEART mode] Client secrets are not allowed" }

            // make sure we've got a key registered
            require(!(client.jwks == null && Strings.isNullOrEmpty(client.jwksUri))) { "[HEART mode] All clients must have a key registered" }

            // make sure our redirect URIs each fit one of the allowed categories
            if (client.redirectUris.isNotEmpty()) {
                var localhost = false
                var remoteHttps = false
                var customScheme = false
                for (uri in client.redirectUris) {
                    val components = UriComponentsBuilder.fromUriString(uri).build()
                    if (components.scheme == null) {
                        // this is a very unknown redirect URI
                        customScheme = true
                    } else if (components.scheme == "http") {
                        // http scheme, check for localhost
                        if (components.host == "localhost" || components.host == "127.0.0.1") {
                            localhost = true
                        } else {
                            throw IllegalArgumentException("[HEART mode] Can't have an http redirect URI on non-local host")
                        }
                    } else if (components.scheme == "https") {
                        remoteHttps = true
                    } else {
                        customScheme = true
                    }
                }

                // now we make sure the client has a URI in only one of each of the three categories
                require(
                    ((localhost xor remoteHttps xor customScheme)
                            && !(localhost && remoteHttps && customScheme))
                ) { "[HEART mode] Can't have more than one class of redirect URI" }
            }
        }
    }

    /**
     * Get the client by its internal ID
     */
    override fun getClientById(id: Long): ClientDetailsEntity? {
        val client = clientRepository.getById(id)

        return client
    }

    /**
     * Get the client for the given ClientID
     */
    @Throws(OAuth2Exception::class, InvalidClientException::class, IllegalArgumentException::class)
    override fun loadClientByClientId(clientId: String): ClientDetailsEntity? {
        require(clientId.isNotEmpty()) { "Client id must not be empty!" }

        return clientRepository.getClientByClientId(clientId)
            ?: throw InvalidClientException("Client with id $clientId was not found")
    }

    /**
     * Delete a client and all its associated tokens
     */
    @Throws(InvalidClientException::class)
    override fun deleteClient(client: ClientDetailsEntity) {
        if (clientRepository.getById(client.id.toJavaId()) == null) {
            throw InvalidClientException("Client with id " + client.clientId + " was not found")
        }

        // clean out any tokens that this client had issued
        tokenRepository.clearTokensForClient(client)

        // clean out any approved sites for this client
        approvedSiteService.clearApprovedSitesForClient(client)

        // clear out any whitelisted sites for this client
        val whitelistedSite = whitelistedSiteService.getByClientId(client.clientId!!)
        if (whitelistedSite != null) {
            whitelistedSiteService.remove(whitelistedSite)
        }

        // clear out resource sets registered for this client
        val resourceSets = resourceSetService.getAllForClient(client)
        for (rs in resourceSets!!) {
            resourceSetService.remove(rs)
        }

        // take care of the client itself
        clientRepository.deleteClient(client)

        statsService.resetCache()
    }

    /**
     * Update the oldClient with information from the newClient. The
     * id from oldClient is retained.
     *
     * Checks to make sure the refresh grant type and
     * the scopes are set appropriately.
     *
     * Checks to make sure the redirect URIs aren't blacklisted.
     *
     * Attempts to load the redirect URI (possibly cached) to check the
     * sector identifier against the contents there.
     *
     *
     */
    @Throws(IllegalArgumentException::class)
    override fun updateClient(oldClient: ClientDetailsEntity?, newClient: ClientDetailsEntity?): ClientDetailsEntity {
        if (oldClient == null || newClient == null) {
            throw IllegalArgumentException("Neither old client or new client can be null!")
        }

        val registeredRedirectUri = newClient.registeredRedirectUri
        if (registeredRedirectUri != null) {
            for (uri in registeredRedirectUri) {
                require(!blacklistedSiteService.isBlacklisted(uri)) { "Client URI is blacklisted: $uri" }
            }
        }

        // if the client is flagged to allow for refresh tokens, make sure it's got the right scope
        ensureRefreshTokenConsistency(newClient)

        // make sure we don't have both a JWKS and a JWKS URI
        ensureKeyConsistency(newClient)

        // check consistency when using HEART mode
        checkHeartMode(newClient)

        // check the sector URI
        checkSectorIdentifierUri(newClient)

        // make sure a client doesn't get any special system scopes
        ensureNoReservedScopes(newClient)

        return clientRepository.updateClient(oldClient.id.toJavaId(), newClient)

    }

    override val allClients: Collection<ClientDetailsEntity>
        /**
         * Get all clients in the system
         */
        get() = clientRepository.allClients

    /**
     * Generates a clientId for the given client and sets it to the client's clientId field. Returns the client that was passed in, now with id set.
     */
    override fun generateClientId(client: ClientDetailsEntity): ClientDetailsEntity {
        client.clientId = UUID.randomUUID().toString()
        return client
    }

    /**
     * Generates a new clientSecret for the given client and sets it to the client's clientSecret field. Returns the client that was passed in, now with secret set.
     */
    override fun generateClientSecret(client: ClientDetailsEntity): ClientDetailsEntity {
        if (config.isHeartMode) {
            logger.error("[HEART mode] Can't generate a client secret, skipping step; client won't be saved due to invalid configuration")
            client.clientSecret = null
        } else {
            client.clientSecret = Base64.encodeBase64URLSafeString(
                BigInteger(512, SecureRandom()).toByteArray()
            ).replace("=", "")
        }
        return client
    }

    /**
     * Utility class to load a sector identifier's set of authorized redirect URIs.
     *
     * @author jricher
     */
    private inner class SectorIdentifierLoader(httpClient: HttpClient?) : CacheLoader<String, List<String>>() {
        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
        private val restTemplate = RestTemplate(httpFactory)
        private val parser = JsonParser()

        @Throws(Exception::class)
        override fun load(key: String): List<String> {
            if (!key.startsWith("https")) {
                require(!config.isForceHttps) { "Sector identifier must start with https: $key" }
                logger.error("Sector identifier doesn't start with https, loading anyway...")
            }

            // key is the sector URI
            val jsonString = restTemplate.getForObject(key, String::class.java)
            val json = parser.parse(jsonString)

            if (json.isJsonArray) {
                val redirectUris: MutableList<String> = ArrayList()
                for (el in json.asJsonArray) {
                    redirectUris.add(el.asString)
                }

                logger.info("Found $redirectUris for sector $key")

                return redirectUris
            } else {
                throw IllegalArgumentException("JSON Format Error")
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DefaultOAuth2ClientDetailsEntityService::class.java)
    }
}