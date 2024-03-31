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
package org.mitre.openid.connect.client

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.apache.http.client.HttpClient
import org.apache.http.client.utils.URIBuilder
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.openid.connect.config.ServerConfiguration.UserInfoTokenMethod
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.mitre.openid.connect.model.UserInfo
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpMethod
import org.springframework.http.client.ClientHttpRequest
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 * Utility class to fetch userinfo from the userinfo endpoint, if available. Caches the results.
 * @author jricher
 */
class UserInfoFetcher(
    httpClient: HttpClient = HttpClientBuilder.create().useSystemProperties().build()
) {
    private val cache: LoadingCache<PendingOIDCAuthenticationToken, UserInfo?> =
        CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(UserInfoLoader(httpClient))

    fun loadUserInfo(token: PendingOIDCAuthenticationToken): UserInfo? {
        try {
            return cache[token]
        } catch (e: UncheckedExecutionException) {
            logger.warn("Couldn't load User Info from token: " + e.message)
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load User Info from token: " + e.message)
        }
        return null
    }


    private inner class UserInfoLoader(httpClient: HttpClient) :
        CacheLoader<PendingOIDCAuthenticationToken, UserInfo?>() {
        private val factory = HttpComponentsClientHttpRequestFactory(httpClient)

        @Throws(URISyntaxException::class)
        override fun load(token: PendingOIDCAuthenticationToken): UserInfo? {
            val serverConfiguration = token.serverConfiguration

            if (serverConfiguration == null) {
                logger.warn("No server configuration found.")
                return null
            }

            if (serverConfiguration.userInfoUri.isNullOrEmpty()) {
                logger.warn("No userinfo endpoint, not fetching.")
                return null
            }

            var userInfoString: String? = null

            if (serverConfiguration.userInfoTokenMethod == null || serverConfiguration.userInfoTokenMethod == UserInfoTokenMethod.HEADER) {
                val restTemplate: RestTemplate = object : RestTemplate(factory) {
                    @Throws(IOException::class)
                    override fun createRequest(url: URI, method: HttpMethod): ClientHttpRequest {
                        val httpRequest = super.createRequest(url, method)
                        httpRequest.headers.add("Authorization", String.format("Bearer %s", token.accessTokenValue))
                        return httpRequest
                    }
                }

                userInfoString = restTemplate.getForObject(serverConfiguration.userInfoUri, String::class.java)
            } else if (serverConfiguration.userInfoTokenMethod == UserInfoTokenMethod.FORM) {
                val form: MultiValueMap<String, String> = LinkedMultiValueMap()
                form.add("access_token", token.accessTokenValue)

                val restTemplate = RestTemplate(factory)
                userInfoString = restTemplate.postForObject(serverConfiguration.userInfoUri, form, String::class.java)
            } else if (serverConfiguration.userInfoTokenMethod == UserInfoTokenMethod.QUERY) {
                val builder = URIBuilder(serverConfiguration.userInfoUri)
                builder.setParameter("access_token", token.accessTokenValue)

                val restTemplate = RestTemplate(factory)
                userInfoString = restTemplate.getForObject(builder.toString(), String::class.java)
            }


            if (!userInfoString.isNullOrEmpty()) {
                val userInfoJson = JsonParser().parse(userInfoString).asJsonObject

                val userInfo = fromJson(userInfoJson)

                return userInfo
            } else {
                // didn't get anything throw exception
                throw IllegalArgumentException("Unable to load user info")
            }
        }
    }

    protected fun fromJson(userInfoJson: JsonObject?): UserInfo {
        return DefaultUserInfo.fromJson(userInfoJson!!)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(UserInfoFetcher::class.java)
    }
}
