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

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.util.Base64
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.oauth2.introspectingfilter.service.IntrospectionAuthorityGranter
import org.mitre.oauth2.introspectingfilter.service.IntrospectionConfigurationService
import org.mitre.oauth2.introspectingfilter.service.impl.SimpleIntrospectionAuthorityGranter
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod
import org.mitre.oauth2.model.RegisteredClient
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod
import org.springframework.http.client.ClientHttpRequest
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.net.URI
import java.util.*

/**
 * This ResourceServerTokenServices implementation introspects incoming tokens at a
 * server's introspection endpoint URL and passes an Authentication object along
 * based on the response from the introspection endpoint.
 * @author jricher
 */
class IntrospectingTokenService @JvmOverloads constructor(
    httpClient: HttpClient? = HttpClientBuilder.create().useSystemProperties().build()
) : ResourceServerTokenServices {
    var introspectionConfigurationService: IntrospectionConfigurationService? = null
    var introspectionAuthorityGranter: IntrospectionAuthorityGranter = SimpleIntrospectionAuthorityGranter()

    /**
     * The default cache expire time in milliseconds. Defaults to 5 minutes.
     */
    var defaultExpireTime: Int = 300000 // 5 minutes in milliseconds
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

    private val factory = HttpComponentsClientHttpRequestFactory(httpClient)

    // Inner class to store in the hash map
    private inner class TokenCacheObject(var token: OAuth2AccessToken, var auth: OAuth2Authentication) {
        var cacheExpire: Date? = null

        init {
            // we don't need to check the cacheTokens values, because this won't actually be added to the cache if cacheTokens is false
            // if the token isn't null we use the token expire time
            // if forceCacheExpireTime is also true, we also make sure that the token expire time is shorter than the default expire time
            if ((token.expiration != null) && (!isForceCacheExpireTime || (token.expiration.time - System.currentTimeMillis() <= defaultExpireTime))) {
                this.cacheExpire = token.expiration
            } else { // if the token doesn't have an expire time, or if the using forceCacheExpireTime the token expire time is longer than the default, then use the default expire time
                val cal = Calendar.getInstance()
                cal.add(Calendar.MILLISECOND, defaultExpireTime)
                this.cacheExpire = cal.time
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
        if (isCacheTokens && authCache.containsKey(key)) {
            val tco = authCache[key]

            if (tco?.cacheExpire != null && tco.cacheExpire!!.after(Date())) {
                return tco
            } else {
                // if the token is expired, don't keep things around.
                authCache.remove(key)
            }
        }
        return null
    }

    private fun createStoredRequest(token: JsonObject): OAuth2Request {
        val clientId = token["client_id"].asString
        val scopes: MutableSet<String> = HashSet()
        if (token.has("scope")) {
            scopes.addAll(OAuth2Utils.parseParameterList(token["scope"].asString))
        }
        val parameters: MutableMap<String, String> = HashMap()
        parameters["client_id"] = clientId
        parameters["scope"] = OAuth2Utils.formatParameterList(scopes)
        val storedRequest = OAuth2Request(parameters, clientId, null, true, scopes, null, null, null, null)
        return storedRequest
    }

    private fun createUserAuthentication(token: JsonObject): Authentication? {
        var userId = token["user_id"]
        if (userId == null) {
            userId = token["sub"]
            if (userId == null) {
                return null
            }
        }

        return PreAuthenticatedAuthenticationToken(userId.asString, token, introspectionAuthorityGranter.getAuthorities(token))
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
    private fun parseToken(accessToken: String): TokenCacheObject? {
        // find out which URL to ask

        val introspectionUrl: String
        val client: RegisteredClient
        try {
            introspectionUrl = introspectionConfigurationService!!.getIntrospectionUrl(accessToken)
            client = introspectionConfigurationService!!.getClientConfiguration(accessToken)
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to load introspection URL or client configuration", e)
            return null
        }
        // Use the SpringFramework RestTemplate to send the request to the
        // endpoint
        var validatedToken: String? = null

        val restTemplate: RestTemplate
        val form: MultiValueMap<String, String?> = LinkedMultiValueMap()

        val clientId = client.clientId
        val clientSecret = client.clientSecret

        if (AuthMethod.SECRET_BASIC == client.tokenEndpointAuthMethod) {
            // use BASIC auth if configured to do so
            restTemplate = object : RestTemplate(factory) {
                @Throws(IOException::class)
                override fun createRequest(url: URI, method: HttpMethod): ClientHttpRequest {
                    val httpRequest = super.createRequest(url, method)
                    httpRequest.headers.add(
                        "Authorization",
                        String.format("Basic %s", Base64.encode(String.format("%s:%s", clientId, clientSecret)))
                    )
                    return httpRequest
                }
            }
        } else {  //Alternatively use form based auth
            restTemplate = RestTemplate(factory)

            form.add("client_id", clientId)
            form.add("client_secret", clientSecret)
        }

        form.add("token", accessToken)

        try {
            validatedToken = restTemplate.postForObject(introspectionUrl, form, String::class.java)
        } catch (rce: RestClientException) {
            logger.error("validateToken", rce)
            return null
        }
        if (validatedToken != null) {
            // parse the json
            val jsonRoot = JsonParser().parse(validatedToken)
            if (!jsonRoot.isJsonObject) {
                return null // didn't get a proper JSON object
            }

            val tokenResponse = jsonRoot.asJsonObject

            if (tokenResponse["error"] != null) {
                // report an error?
                logger.error("Got an error back: " + tokenResponse["error"] + ", " + tokenResponse["error_description"])
                return null
            }

            if (!tokenResponse["active"].asBoolean) {
                // non-valid token
                logger.info("Server returned non-active token")
                return null
            }
            // create an OAuth2Authentication
            val auth = OAuth2Authentication(createStoredRequest(tokenResponse), createUserAuthentication(tokenResponse))
            // create an OAuth2AccessToken
            val token = createAccessToken(tokenResponse, accessToken)

            if (token.expiration == null || token.expiration.after(Date())) {
                // Store them in the cache
                val tco = TokenCacheObject(token, auth)
                if (isCacheTokens && (isCacheNonExpiringTokens || token.expiration != null)) {
                    authCache[accessToken] = tco
                }
                return tco
            }
        }

        // when the token is invalid for whatever reason
        return null
    }

    @Throws(AuthenticationException::class)
    override fun loadAuthentication(accessToken: String): OAuth2Authentication? {
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

    override fun readAccessToken(accessToken: String): OAuth2AccessToken? {
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

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(IntrospectingTokenService::class.java)
    }
}