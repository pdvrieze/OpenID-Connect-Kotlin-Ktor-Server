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

import io.github.pdvrieze.client.CoroutineCache
import io.github.pdvrieze.client.onError
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.json.Json
import org.mitre.openid.connect.config.ServerConfiguration.UserInfoTokenMethod
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.mitre.openid.connect.model.UserInfo
import org.mitre.util.getLogger
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

/**
 * Utility class to fetch userinfo from the userinfo endpoint, if available. Caches the results.
 * @author jricher
 */
class UserInfoFetcher(
    private val httpClient: HttpClient = HttpClient(CIO)
) {

    private val cache = CoroutineCache<PendingOIDCAuthenticationToken, UserInfo?>(::loadUserInfoImpl) {
        expireAfterWrite(1.seconds.toJavaDuration())
        maximumSize(100)
    }

    suspend fun loadUserInfo(token: PendingOIDCAuthenticationToken): UserInfo? {
        return cache.load(token)
    }

    suspend fun loadUserInfoImpl(token: PendingOIDCAuthenticationToken): UserInfo? {
        val serverConfiguration = token.serverConfiguration

        if (serverConfiguration == null) {
            logger.warn("No server configuration found.")
            return null
        }

        val userInfoUri = serverConfiguration.userInfoUri
        if (userInfoUri.isNullOrEmpty()) {
            logger.warn("No userinfo endpoint, not fetching.")
            return null
        }


        val tokenMethod = serverConfiguration.userInfoTokenMethod
        val response: HttpResponse = when (tokenMethod) {
            null, UserInfoTokenMethod.HEADER -> {
                httpClient.get(userInfoUri) {
                    bearerAuth(token.accessTokenValue)
                }
            }

            UserInfoTokenMethod.FORM -> {
                httpClient.post(userInfoUri) {
                    formData {
                        append("access_token", token.accessTokenValue)
                    }
                }
            }
            UserInfoTokenMethod.QUERY -> {
                val builder = URLBuilder(userInfoUri).apply { parametersOf("access_token", token.accessTokenValue) }

                httpClient.get(builder.build())
            }
        }
        response.onError { throw IllegalArgumentException("Unable to load user info: $it") }

        val userInfoString = response.bodyAsText()

        if (userInfoString.isEmpty()) { // didn't get anything throw exception
            throw IllegalArgumentException("Unable to load user info")
        }

        return Json.decodeFromString<DefaultUserInfo>(userInfoString)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<UserInfoFetcher>()
    }
}
