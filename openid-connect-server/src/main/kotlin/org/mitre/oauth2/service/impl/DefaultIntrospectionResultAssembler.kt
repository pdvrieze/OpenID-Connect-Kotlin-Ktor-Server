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

import com.google.common.base.Joiner
import com.google.common.collect.Maps
import com.google.common.collect.Sets
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.openid.connect.model.UserInfo
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.text.ParseException

/**
 * Default implementation of the [IntrospectionResultAssembler] interface.
 */
@Service
class DefaultIntrospectionResultAssembler : IntrospectionResultAssembler {
    override fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): Map<String, Any> {
        val result: MutableMap<String, Any> = Maps.newLinkedHashMap()
        val authentication = accessToken.authenticationHolder.authentication

        result[IntrospectionResultAssembler.ACTIVE] = true

        val accessPermissions = accessToken.permissions
        if (!accessPermissions.isNullOrEmpty()) {
            result["permissions"] = accessPermissions.mapTo(HashSet<Map<String, Any>>()) { perm ->
                hashMapOf(
                    "resource_set_id" to perm.resourceSet!!.id.toString(),
                    "scopes" to (perm.scopes?.toHashSet() ?: emptySet()),
                )
            }
        } else {
            val scopes = accessToken.scope?.let { authScopes.intersect(it) } ?: emptySet()

            result[IntrospectionResultAssembler.SCOPE] = scopes.joinToString(IntrospectionResultAssembler.SCOPE_SEPARATOR)
        }

        val expiration = accessToken.expiration
        if (expiration != null) {
            try {
                result[IntrospectionResultAssembler.EXPIRES_AT] =
                    IntrospectionResultAssembler.dateFormat.valueToString(expiration)
                result[IntrospectionResultAssembler.EXP] = expiration.time / 1000L
            } catch (e: ParseException) {
                logger.error("Parse exception in token introspection", e)
            }
        }

        if (userInfo != null) {
            // if we have a UserInfo, use that for the subject
            result[IntrospectionResultAssembler.SUB] = userInfo.sub!!
        } else {
            // otherwise, use the authentication's username
            result[IntrospectionResultAssembler.SUB] = authentication.name
        }

        if (authentication.userAuthentication != null) {
            result[IntrospectionResultAssembler.USER_ID] = authentication.userAuthentication.name
        }

        result[IntrospectionResultAssembler.CLIENT_ID] = authentication.oAuth2Request.clientId

        result[IntrospectionResultAssembler.TOKEN_TYPE] = accessToken.tokenType

        return result
    }

    override fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>
    ): Map<String, Any> {
        val result: MutableMap<String, Any> = Maps.newLinkedHashMap()
        val authentication = refreshToken.authenticationHolder!!.authentication

        result[IntrospectionResultAssembler.ACTIVE] = true

        val scopes: Set<String> = Sets.intersection(authScopes, authentication.oAuth2Request.scope)

        result[IntrospectionResultAssembler.SCOPE] =
            Joiner.on(IntrospectionResultAssembler.SCOPE_SEPARATOR).join(scopes)

        val expiration = refreshToken.expiration
        if (expiration != null) {
            try {
                result[IntrospectionResultAssembler.EXPIRES_AT] =
                    IntrospectionResultAssembler.dateFormat.valueToString(expiration)
                result[IntrospectionResultAssembler.EXP] = expiration.time / 1000L
            } catch (e: ParseException) {
                logger.error("Parse exception in token introspection", e)
            }
        }


        if (userInfo != null) {
            // if we have a UserInfo, use that for the subject
            result[IntrospectionResultAssembler.SUB] = userInfo.sub!!
        } else {
            // otherwise, use the authentication's username
            result[IntrospectionResultAssembler.SUB] = authentication.name
        }

        if (authentication.userAuthentication != null) {
            result[IntrospectionResultAssembler.USER_ID] = authentication.userAuthentication.name
        }

        result[IntrospectionResultAssembler.CLIENT_ID] = authentication.oAuth2Request.clientId

        return result
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DefaultIntrospectionResultAssembler::class.java)
    }
}
