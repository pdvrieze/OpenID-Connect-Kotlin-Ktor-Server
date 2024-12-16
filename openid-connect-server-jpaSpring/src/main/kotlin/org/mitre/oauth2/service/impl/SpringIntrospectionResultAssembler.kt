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
package org.mitre.oauth2.service.impl

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.openid.connect.model.UserInfo
import org.mitre.util.getLogger
import org.springframework.stereotype.Service
import java.text.ParseException
import java.time.Instant

/**
 * Default implementation of the [IntrospectionResultAssembler] interface.
 */
@Service
class SpringIntrospectionResultAssembler : IntrospectionResultAssembler {
    override fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): Map<String, Any> {
        val result: MutableMap<String, Any> = mutableMapOf()
        val authentication = accessToken.authenticationHolder

        result[IntrospectionResultAssembler.ACTIVE] = true

        val accessPermissions = accessToken.permissions
        if (!accessPermissions.isNullOrEmpty()) {
            result["permissions"] = accessPermissions.mapTo(HashSet<Map<String, Any>>()) { perm ->
                hashMapOf(
                    "resource_set_id" to perm.resourceSet.id.toString(),
                    "scopes" to perm.scopes.toHashSet(),
                )
            }
        } else {
            val scopes = accessToken.scope.let { authScopes.intersect(it) }

            result[IntrospectionResultAssembler.SCOPE] =
                scopes.joinToString(IntrospectionResultAssembler.SCOPE_SEPARATOR)
        }

        val expiration = accessToken.expirationInstant
        if (expiration > Instant.MIN) {
            try {
                result[IntrospectionResultAssembler.EXPIRES_AT] =
                    IntrospectionResultAssembler.dateFormat.format(expiration)
                result[IntrospectionResultAssembler.EXP] = expiration.epochSecond
            } catch (e: ParseException) {
                logger.error("Parse exception in token introspection", e)
            }
        }

        if (userInfo != null) {
            // if we have a UserInfo, use that for the subject
            result[IntrospectionResultAssembler.SUB] = userInfo.subject
        } else {
            // otherwise, use the authentication's username
            result[IntrospectionResultAssembler.SUB] = authentication.principalName
        }

        authentication.subjectAuth?.let {
            result[IntrospectionResultAssembler.USER_ID] = it.principalName
        }

        result[IntrospectionResultAssembler.CLIENT_ID] = authentication.authorizationRequest.clientId

        result[IntrospectionResultAssembler.TOKEN_TYPE] = accessToken.tokenType

        return result
    }

    override fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): Map<String, Any> {
        val result: MutableMap<String, Any> = mutableMapOf()
        val authentication = refreshToken.authenticationHolder

        result[IntrospectionResultAssembler.ACTIVE] = true

        val scopes: Set<String> = authScopes.intersect(authentication.authorizationRequest.scope)

        result[IntrospectionResultAssembler.SCOPE] =
            scopes.joinToString(IntrospectionResultAssembler.SCOPE_SEPARATOR)

        val expiration = refreshToken.expirationInstant
        if (expiration > Instant.MIN) {
            try {
                result[IntrospectionResultAssembler.EXPIRES_AT] =
                    IntrospectionResultAssembler.dateFormat.format(expiration)
                result[IntrospectionResultAssembler.EXP] = expiration.epochSecond
            } catch (e: ParseException) {
                logger.error("Parse exception in token introspection", e)
            }
        }


        if (userInfo != null) {
            // if we have a UserInfo, use that for the subject
            result[IntrospectionResultAssembler.SUB] = userInfo.subject
        } else {
            // otherwise, use the authentication's username
            result[IntrospectionResultAssembler.SUB] = authentication.principalName
        }

        authentication.subjectAuth?.let {
            result[IntrospectionResultAssembler.USER_ID] = it.principalName
        }

        result[IntrospectionResultAssembler.CLIENT_ID] = authentication.authorizationRequest.clientId

        return result
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<SpringIntrospectionResultAssembler>()
    }
}
