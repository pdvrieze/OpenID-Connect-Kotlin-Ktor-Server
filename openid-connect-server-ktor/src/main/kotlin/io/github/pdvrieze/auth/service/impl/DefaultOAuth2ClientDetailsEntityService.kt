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

import com.github.benmanes.caffeine.cache.CacheLoader
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.java.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.ClientLoadingResult
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.util.requireId
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.uma.service.ResourceSetService
import org.mitre.util.asString
import org.mitre.util.getLogger
import java.math.BigInteger
import java.net.URI
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class DefaultOAuth2ClientDetailsEntityService(
    private val clientRepository: OAuth2ClientRepository,
    private val tokenRepository: OAuth2TokenRepository,
    private val approvedSiteService: ApprovedSiteService,
    private val whitelistedSiteService: WhitelistedSiteService,
    private val blacklistedSiteService: BlacklistedSiteService,
    private val scopeService: SystemScopeService,
    private val statsService: StatsService,
    private val resourceSetService: ResourceSetService,
    private val config: ConfigurationPropertiesBean,
) : ClientDetailsEntityService {

    // map of sector URI -> list of redirect URIs
    private val sectorRedirects: LoadingCache<String, List<String>> = Caffeine.newBuilder()
        .expireAfterAccess(1, TimeUnit.HOURS)
        .maximumSize(100)
        .build(SectorIdentifierLoader(HttpClient(Java) {}))

    override fun saveNewClient(client: OAuthClientDetails.Builder): OAuthClientDetails {
        require(client.id == null) {  // if it's not null, it's already been saved, this is an error
            "Tried to save a new client with an existing ID: ${client.id}"
        }

        val redirectUris = client.redirectUris
        for (uri in redirectUris) {
            require(!blacklistedSiteService.isBlacklisted(uri)) { "Client URI is blacklisted: $uri" }
        }

        // assign a random clientid if it's empty
        // NOTE: don't assign a random client secret without asking, since public clients have no secret
        if (client.clientId.isNullOrEmpty()) {
            client.clientId = generateClientIdString(client.build())
        }

        // make sure that clients with the "refresh_token" grant type have the "offline_access" scope, and vice versa
        ensureRefreshTokenConsistency(client)

        // make sure we don't have both a JWKS and a JWKS URI
        ensureKeyConsistency(client)

        // check consistency when using HEART mode
        checkHeartMode(client)


        // check the sector URI
        checkSectorIdentifierUri(client)


        ensureNoReservedScopes(client)
        require(! client.scope.isNullOrEmpty()) { "No valid scope for client" }

        client.createdAt = Date()

        val c = clientRepository.saveClient(client.build())

        statsService.resetCache()

        return ClientDetailsEntity.from(c)
    }

    /**
     * Make sure the client has only one type of key registered
     */
    private fun ensureKeyConsistency(client: OAuthClientDetails.Builder) {
        require(!(client.jwksUri != null && client.jwks != null)) {
            // a client can only have one key type or the other, not both
            "A client cannot have both JWKS URI and JWKS value"
        }
    }

    /**
     * Make sure the client doesn't request any system reserved scopes
     */
    private fun ensureNoReservedScopes(client: OAuthClientDetails.Builder) {
        val scope = scopeService.fromStrings(client.scope)
        client.scope?.clear()
        if (scope !=null) {
            when (val s = client.scope) {
                null -> client.scope = scopeService.toStrings(scopeService.removeReservedScopes(scope))?.toHashSet()
                else -> s.addAll(scopeService.toStrings(scopeService.removeReservedScopes(scope))!!)
            }
        }
    }

    /**
     * Load the sector identifier URI if it exists and check the redirect URIs against it
     */
    private fun checkSectorIdentifierUri(client: OAuthClientDetails.Builder) {
        if (!client.sectorIdentifierUri.isNullOrEmpty()) {
            try {
                val redirects = sectorRedirects[client.sectorIdentifierUri]

                val redirectUris = client.redirectUris
                for (uri in redirectUris) {
                    require(redirects.contains(uri)) { "Requested Redirect URI $uri is not listed at sector identifier $redirects" }
                }
            } catch (e: ExecutionException) {
                throw IllegalArgumentException("Unable to load sector identifier URI ${client.sectorIdentifierUri}: ${e.message}")
            }
        }
    }

    /**
     * Make sure the client has the appropriate scope and grant type.
     */
    private fun ensureRefreshTokenConsistency(client: OAuthClientDetails.Builder) {
        val s = client.scope
        if ("refresh_token" in client.authorizedGrantTypes
            || (s != null && SystemScopeService.OFFLINE_ACCESS in s)
        ) {
            if (s == null) client.scope = hashSetOf()
            client.scope!!.add(SystemScopeService.OFFLINE_ACCESS)
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
    private fun checkHeartMode(client: OAuthClientDetails.Builder) {
        if (config.isHeartMode) {
            if (client.authorizedGrantTypes.contains("authorization_code")) {
                // make sure we don't have incompatible grant types
                require(!(client.authorizedGrantTypes.contains("implicit") || client.authorizedGrantTypes.contains("client_credentials"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.PRIVATE_KEY)) { "[HEART mode] Authorization code clients must use the private_key authentication method" }

                // make sure we've got a redirect URI
                require(!client.redirectUris.isEmpty()) { "[HEART mode] Authorization code clients must register at least one redirect URI" }
            }

            if (client.authorizedGrantTypes.contains("implicit")) {
                // make sure we don't have incompatible grant types
                require(!(client.authorizedGrantTypes.contains("authorization_code") || client.authorizedGrantTypes.contains("client_credentials") || client.authorizedGrantTypes.contains("refresh_token"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.NONE)) { "[HEART mode] Implicit clients must use the none authentication method" }

                // make sure we've got a redirect URI
                require(!client.redirectUris.isEmpty()) { "[HEART mode] Implicit clients must register at least one redirect URI" }
            }

            if (client.authorizedGrantTypes.contains("client_credentials")) {
                // make sure we don't have incompatible grant types
                require(!(client.authorizedGrantTypes.contains("authorization_code") || client.authorizedGrantTypes.contains("implicit") || client.authorizedGrantTypes.contains("refresh_token"))) { "[HEART mode] Incompatible grant types" }

                // make sure we've got the right authentication method
                require(!(client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod != AuthMethod.PRIVATE_KEY)) { "[HEART mode] Client credentials clients must use the private_key authentication method" }

                // make sure we've got a redirect URI
                require(client.redirectUris.isEmpty()) { "[HEART mode] Client credentials clients must not register a redirect URI" }
            }

            require(!client.authorizedGrantTypes.contains("password")) { "[HEART mode] Password grant type is forbidden" }

            // make sure we don't have a client secret
            require(client.clientSecret.isNullOrEmpty()) { "[HEART mode] Client secrets are not allowed" }

            // make sure we've got a key registered
            require(!(client.jwks == null && client.jwksUri.isNullOrEmpty())) { "[HEART mode] All clients must have a key registered" }

            // make sure our redirect URIs each fit one of the allowed categories
            if (client.redirectUris.isNotEmpty()) {
                var localhost = false
                var remoteHttps = false
                var customScheme = false
                for (uri in client.redirectUris) {
                    val parsedUri = URI(uri)
                    val scheme = parsedUri.scheme
                    if (scheme == null) {
                        // this is a very unknown redirect URI
                        customScheme = true
                    } else if (scheme == "http") {
                        val host = parsedUri.host
                        // http scheme, check for localhost
                        if (host == "localhost" || host == "127.0.0.1") {
                            localhost = true
                        } else {
                            throw IllegalArgumentException("[HEART mode] Can't have an http redirect URI on non-local host")
                        }
                    } else if (scheme == "https") {
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
    override fun getClientById(id: Long): OAuthClientDetails? {
        val client = clientRepository.getById(id)

        return client?.let(ClientDetailsEntity::from)
    }

    /**
     * Get the client for the given ClientID
     */
    override fun loadClientByClientId(clientId: String): ClientDetailsEntity {
        require(clientId.isNotEmpty()) { "Client id must not be empty!" }

        return clientRepository.getClientByClientId(clientId)
            ?.let(ClientDetailsEntity::from)
            ?: throw InvalidClientException("Client with id $clientId was not found")
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun loadClientAuthenticated(clientId: String, clientPublicSecret: String): ClientLoadingResult {
        val client = clientRepository.getClientByClientId(clientId)?: return ClientLoadingResult.Missing
        val clientSecret = client.clientSecret ?: return ClientLoadingResult.Unauthorized // don't allow unauthorized clients
        val pwdIdx = clientSecret.indexOf(':')
        if (pwdIdx >=0) {
            val salt = clientSecret.substring(0, pwdIdx)
            val expectedDigest = Base64.Default.decode(clientSecret.substring(pwdIdx + 1))
            val actualDigest = getDigestFunction("SHA-256", { salt }).invoke(clientPublicSecret)
            if (!expectedDigest.contentEquals(actualDigest)) {return ClientLoadingResult.Unauthorized}
        } else if (clientSecret != clientPublicSecret) return ClientLoadingResult.Unauthorized

        return ClientLoadingResult.Found(client)
    }

    /**
     * Delete a client and all its associated tokens
     */
    override fun deleteClient(client: OAuthClientDetails) {
        if (clientRepository.getById(client.id.requireId()) == null) {
            throw InvalidClientException("Client with id ${client.clientId} was not found")
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
        for (rs in resourceSets) {
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
    override fun updateClient(oldClient: OAuthClientDetails, newClient: OAuthClientDetails): OAuthClientDetails {

        for (uri in newClient.redirectUris) {
            require(!blacklistedSiteService.isBlacklisted(uri)) { "Client URI is blacklisted: $uri" }
        }

        val newClientBuilder = newClient.builder()

        // if the client is flagged to allow for refresh tokens, make sure it's got the right scope
        ensureRefreshTokenConsistency(newClientBuilder)

        // make sure we don't have both a JWKS and a JWKS URI
        ensureKeyConsistency(newClientBuilder)

        // check consistency when using HEART mode
        checkHeartMode(newClientBuilder)

        // check the sector URI
        checkSectorIdentifierUri(newClientBuilder)

        // make sure a client doesn't get any special system scopes
        ensureNoReservedScopes(newClientBuilder)!!

        val cleanedClient = newClientBuilder.build()

        return clientRepository.updateClient(oldClient.id.requireId(), cleanedClient).let(ClientDetailsEntity::from)

    }

    override val allClients: Collection<OAuthClientDetails>
        /**
         * Get all clients in the system
         */
        get() = clientRepository.allClients.map(ClientDetailsEntity::from)

    /**
     * Generates a clientId for the given client and sets it to the client's clientId field. Returns the client that was passed in, now with id set.
     */
    override fun generateClientIdString(client: OAuthClientDetails): String {
        return UUID.randomUUID().toString()
    }

    /**
     * Generates a new clientSecret for the given client and sets it to the client's clientSecret field. Returns the client that was passed in, now with secret set.
     */
    @OptIn(ExperimentalEncodingApi::class)
    override fun generateClientSecret(client: OAuthClientDetails.Builder?): String? {
        if (config.isHeartMode) {
            logger.error("[HEART mode] Can't generate a client secret, skipping step; client won't be saved due to invalid configuration")
            return null
        } else {
            return Base64.UrlSafe.encode(
                BigInteger(512, SecureRandom()).toByteArray()
            ).replace("=", "")
        }
    }

    /**
     * Utility class to load a sector identifier's set of authorized redirect URIs.
     *
     * @author jricher
     */
    private inner class SectorIdentifierLoader(private val httpClient: HttpClient = HttpClient(Java) {}) :
        CacheLoader<String, List<String>> {
//        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
//        private val restTemplate = RestTemplate(httpFactory)

        @Throws(Exception::class)
        override fun load(url: String): List<String> {
            if (!url.startsWith("https")) {
                require(!config.isForceHttps) { "Sector identifier must start with https: $url" }
                logger.error("Sector identifier doesn't start with https, loading anyway...")
            }

            // key is the sector URI
            val jsonString = runBlocking {
                val response = httpClient.get(urlString = url) {
                }
                if (! response.status.isSuccess()) throw AuthenticationException("Request to $url failed with code: ${response.status}")
                response.bodyAsText()
            }

            val json = runBlocking {
                httpClient.get(url).body<List<JsonPrimitive>>()
            }

/*
//                restTemplate.getForObject(url, String::class.java)
            val json2 = requireNotNull(MITREidDataService.json.parseToJsonElement(jsonString) as? JsonArray) {
                "JSON Format Error"
            }
*/

            val redirectUris: List<String> = json.map { it.asString() }

            logger.info("Found $redirectUris for sector $url")

            return redirectUris
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DefaultOAuth2ClientDetailsEntityService>()
    }
}
