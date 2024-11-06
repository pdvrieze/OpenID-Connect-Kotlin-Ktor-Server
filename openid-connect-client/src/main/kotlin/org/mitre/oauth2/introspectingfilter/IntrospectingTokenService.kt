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
package org.mitre.oauth2.introspectingfilter

import com.nimbusds.jose.util.Base64
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.mitre.oauth2.introspectingfilter.service.IntrospectionAuthorityGranter
import org.mitre.oauth2.introspectingfilter.service.IntrospectionConfigurationService
import org.mitre.oauth2.introspectingfilter.service.impl.SimpleIntrospectionAuthorityGranter
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.LocalGrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.util.asBoolean
import org.mitre.util.getLogger
import java.time.Instant
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

/**
 * This ResourceServerTokenServices implementation introspects incoming tokens at a
 * server's introspection endpoint URL and passes an Authentication object along
 * based on the response from the introspection endpoint.
 * @author jricher
 */
class IntrospectingTokenService(
    private var introspectionConfigurationService: IntrospectionConfigurationService,
    private val httpClient: HttpClient = HttpClient(CIO),
    private var introspectionAuthorityGranter: IntrospectionAuthorityGranter = SimpleIntrospectionAuthorityGranter(),

) {

    /**
     * The default cache expire time in milliseconds. Defaults to 5 minutes.
     */
    var defaultExpireTime: java.time.Duration = 5.minutes.toJavaDuration()

    /**
     * Force removal of cached tokens based on default expire time
     */
    var isForceCacheExpireTime: Boolean = false

    /**
     * Are non-expiring tokens cached using the default cache time
     */
    var isCacheNonExpiringTokens: Boolean = false

    /**
     * Is the service caching tokens, or is it hitting the introspection end point every time.
     * `true` is caching tokens locally, `false` hits the introspection end point every time
     */
    var isCacheTokens: Boolean = true

    // Inner class to store in the hash map
    private inner class TokenCacheObject(var token: OAuth2AccessToken, var auth: AuthenticatedAuthorizationRequest) {
        var cacheExpire: Instant? = null

        init {
            // we don't need to check the cacheTokens values, because this won't actually be added to the cache if cacheTokens is false
            // if the token isn't null we use the token expire time
            // if forceCacheExpireTime is also true, we also make sure that the token expire time is shorter than the default expire time
            val now = Instant.now()

            if ((token.expirationInstant>Instant.MIN) && (!isForceCacheExpireTime || (token.expirationInstant < (now + defaultExpireTime)))) {
                this.cacheExpire = token.expirationInstant
            } else { // if the token doesn't have an expire time, or if the using forceCacheExpireTime the token expire time is longer than the default, then use the default expire time
                this.cacheExpire = now + defaultExpireTime
            }
        }
    }

    private val authCache: MutableMap<String, TokenCacheObject> = HashMap()

    /**
     * Check to see if the introspection end point response for a token has been cached locally
     * This call will return the token if it has been cached and is still valid according to
     * the cache expire time on the TokenCacheObject. If a cached value has been found but is
     * expired, either by default expire times or the token's own expire time, then the token is
     * removed from the cache and null is returned.
     * @param key is the token to check
     * @return the cached TokenCacheObject or null
     */
    private fun checkCache(key: String): TokenCacheObject? {
        if (isCacheTokens) {
            val tco = authCache[key]
            if (tco != null) {
                val cacheExpire = tco.cacheExpire
                if (cacheExpire != null && cacheExpire.isAfter(Instant.now())) {
                    return tco
                } else {
                    // if the token is expired, don't keep things around.
                    authCache.remove(key)
                }
            }
        }
        return null
    }

    private fun createStoredRequest(token: JsonObject): AuthorizationRequest {
        return json.decodeFromJsonElement(AuthorizationRequest.serializer(), token)
    }

    private fun createUserAuthentication(token: JsonObject): Authentication? {
        val userId = (token["user_id"] ?: token["sub"] ?: return null).jsonPrimitive
        if (!userId.isString) return null
        val authorities = introspectionAuthorityGranter.getAuthorities(token).map { LocalGrantedAuthority(it.authority) }
        return PreAuthenticatedAuthenticationToken(userId.content, token, authorities)
    }

    private fun createAccessToken(token: JsonObject, tokenString: String): OAuth2AccessToken {
        val accessToken: OAuth2AccessToken = OAuth2AccessTokenImpl(token, tokenString)
        return accessToken
    }

    /**
     * Validate a token string against the introspection endpoint,
     * then parse it and store it in the local cache if caching is enabled.
     *
     * @param accessToken Token to pass to the introspection endpoint
     * @return TokenCacheObject containing authentication and token if the token was valid, otherwise null
     */
    private suspend fun parseToken(accessToken: String): TokenCacheObject? {
        // find out which URL to ask

        val introspectionUrl: String
        val client: RegisteredClient
        try {
            introspectionUrl = introspectionConfigurationService.getIntrospectionUrl(accessToken)
            client = introspectionConfigurationService.getClientConfiguration(accessToken)
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to load introspection URL or client configuration", e)
            return null
        }
        // Use the SpringFramework RestTemplate to send the request to the
        // endpoint

        val requestBuilder = HttpRequestBuilder(introspectionUrl)
        val form = ParametersBuilder()

        val clientId = client.clientId
        val clientSecret = client.clientSecret ?: return null

        if (AuthMethod.SECRET_BASIC == client.tokenEndpointAuthMethod) {
            // use BASIC auth if configured to do so
            requestBuilder.header(
                HttpHeaders.Authorization,
                String.format("Basic %s", Base64.encode(String.format("%s:%s", clientId, clientSecret)))
            )
        } else {  //Alternatively use form based auth
            form.append("client_id", clientId)
            form.append("client_secret", clientSecret)
        }

        form.append("token", accessToken)

        val response = httpClient.request(requestBuilder)
        if (! response.status.isSuccess()) {
            logger.error("Could not look up the token")
            return null
        }

        val validatedToken = response.bodyAsText()

        // parse the json
        val tokenResponse = (json.parseToJsonElement(validatedToken) as? JsonObject) ?: return null

        if (tokenResponse["error"] != null) {
            // report an error?
            logger.error("Got an error back: ${tokenResponse["error"]}, ${tokenResponse["error_description"]}")
            return null
        }

        if (!tokenResponse["active"].asBoolean()) {
            // non-valid token
            logger.info("Server returned non-active token")
            return null
        }
        // create an OAuth2Authentication
        val userAuth = createUserAuthentication(tokenResponse)?.let {
            it as? SavedUserAuthentication ?: SavedUserAuthentication(it)
        }
        val auth = AuthenticatedAuthorizationRequest(createStoredRequest(tokenResponse), userAuth)
        // create an OAuth2AccessToken
        val token = createAccessToken(tokenResponse, accessToken)

        if (token.expirationInstant.isAfter(Instant.now())) {
            // Store them in the cache
            val tco = TokenCacheObject(token, auth)
            if (isCacheTokens && (isCacheNonExpiringTokens || token.expirationInstant.isAfter(Instant.MIN))) {
                authCache[accessToken] = tco
            }
            return tco
        }

        // when the token is invalid for whatever reason
        return null
    }

    private suspend fun loadAuthentication(accessToken: String): AuthenticatedAuthorizationRequest? {
        // First check if the in memory cache has an Authentication object, and
        // that it is still valid
        // If Valid, return it
        var cacheAuth = checkCache(accessToken)
        if (cacheAuth != null) {
            return cacheAuth.auth
        } else {
            cacheAuth = parseToken(accessToken)
            return cacheAuth?.auth
        }
    }

    suspend fun readAccessToken(accessToken: String): OAuth2AccessToken? {
        // First check if the in memory cache has a Token object, and that it is
        // still valid
        // If Valid, return it
        var cacheAuth = checkCache(accessToken)
        if (cacheAuth != null) {
            return cacheAuth.token
        } else {
            cacheAuth = parseToken(accessToken)
            return cacheAuth?.token
        }
    }

    class PreAuthenticatedAuthenticationToken(
        override val name: String,
        val credentials: Any,
        override val authorities: Collection<GrantedAuthority>,
    ) : Authentication {
        override val isAuthenticated: Boolean get() = true
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<IntrospectingTokenService>()

        val json: Json = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
            prettyPrintIndent = "  "
        }

    }
}

