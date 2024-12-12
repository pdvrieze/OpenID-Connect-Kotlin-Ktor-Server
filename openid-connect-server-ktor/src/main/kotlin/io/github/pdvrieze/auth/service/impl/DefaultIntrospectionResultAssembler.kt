/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package io.github.pdvrieze.auth.service.impl

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.openid.connect.model.UserInfo
import org.mitre.util.getLogger
import java.text.ParseException
import java.time.Instant
import java.util.*

/**
 * Default implementation of the [IntrospectionResultAssembler] interface.
 */
class DefaultIntrospectionResultAssembler : JsonIntrospectionResultAssembler {
    override fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): JsonObject {
        val result = buildJsonObject {
            val result = this
            val authentication = accessToken.authenticationHolder


            put(IntrospectionResultAssembler.ACTIVE, true)

            val accessPermissions = accessToken.permissions
            if (!accessPermissions.isNullOrEmpty()) {
                putJsonArray("permissions") {
                    for (perm in accessPermissions) {
                        addJsonObject {
                            put("resource_set_id", perm.resourceSet.id.toString())
                            putJsonArray("scopes") { addAll(perm.scopes) }
                        }
                    }
                }
            } else {
                val scopes = authScopes.intersect(accessToken.scope)

                put(IntrospectionResultAssembler.SCOPE, scopes.joinToString(IntrospectionResultAssembler.SCOPE_SEPARATOR))
            }

            val expiration = accessToken.expirationInstant
            if (expiration > Instant.MIN) {
                try {
                    put(IntrospectionResultAssembler.EXPIRES_AT, IntrospectionResultAssembler.dateFormat.format(expiration))
                    put(IntrospectionResultAssembler.EXP, expiration.epochSecond)
                } catch (e: ParseException) {
                    logger.error("Parse exception in token introspection", e)
                }
            }

            if (userInfo != null) {
                // if we have a UserInfo, use that for the subject
                put(IntrospectionResultAssembler.SUB, userInfo.subject)
            } else {
                // otherwise, use the authentication's username
                put(IntrospectionResultAssembler.SUB, authentication.principalName)
            }

            authentication.userAuthentication?.let {
                put(IntrospectionResultAssembler.USER_ID, it.principalName)
            }

            put(IntrospectionResultAssembler.CLIENT_ID, authentication.authorizationRequest.clientId)

            put(IntrospectionResultAssembler.TOKEN_TYPE, accessToken.tokenType)
        }

        return result
    }

    override fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): JsonObject {
        val result = buildJsonObject {
            val authentication = refreshToken.authenticationHolder

            put(IntrospectionResultAssembler.ACTIVE, true)

            val scopes: Set<String> = authScopes.intersect(authentication.authorizationRequest.scope)

            put(IntrospectionResultAssembler.SCOPE, scopes.joinToString(IntrospectionResultAssembler.SCOPE_SEPARATOR))

            val expiration = refreshToken.expirationInstant
            if (expiration > Instant.MIN) {
                try {
                    val d = Date.from(expiration)
                    put(IntrospectionResultAssembler.EXPIRES_AT, IntrospectionResultAssembler.dateFormat.format(expiration))
                    put(IntrospectionResultAssembler.EXP, expiration.epochSecond)
                } catch (e: ParseException) {
                    logger.error("Parse exception in token introspection", e)
                }
            }


            if (userInfo != null) {
                // if we have a UserInfo, use that for the subject
                put(IntrospectionResultAssembler.SUB, userInfo.subject)
            } else {
                // otherwise, use the authentication's username
                put(IntrospectionResultAssembler.SUB, authentication.principalName)
            }

            authentication.userAuthentication?.let {
                put(IntrospectionResultAssembler.USER_ID, it.principalName)
            }

            put(IntrospectionResultAssembler.CLIENT_ID, authentication.authorizationRequest.clientId)
        }
        return result
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DefaultIntrospectionResultAssembler>()
    }
}
