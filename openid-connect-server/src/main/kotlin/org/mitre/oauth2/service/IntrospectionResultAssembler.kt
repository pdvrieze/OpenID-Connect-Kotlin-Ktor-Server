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
package org.mitre.oauth2.service

import kotlinx.serialization.json.JsonObject
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.openid.connect.model.UserInfo
import java.text.SimpleDateFormat
import javax.swing.text.DateFormatter

interface JsonIntrospectionResultAssembler : IntrospectionResultAssembler {
    override fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>,
    ): JsonObject

    override fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>,
    ): JsonObject
}

/**
 * Strategy interface for assembling a token introspection result.
 */
interface IntrospectionResultAssembler {
    /**
     * Assemble a token introspection result from the given access token and user info.
     *
     * @param accessToken the access token
     * @param userInfo the user info
     * @param authScopes the scopes the client is authorized for
     * @return the token introspection result
     */
    fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity, userInfo: UserInfo?, authScopes: Set<String>
    ): Map<String, Any>

    /**
     * Assemble a token introspection result from the given refresh token and user info.
     *
     * @param refreshToken the refresh token
     * @param userInfo the user info
     * @param authScopes the scopes the client is authorized for
     * @return the token introspection result
     */
    fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity, userInfo: UserInfo?, authScopes: Set<String>
    ): Map<String, Any>

    companion object {
        @JvmField
        val TOKEN_TYPE: String = "token_type"

        @JvmField
        val CLIENT_ID: String = "client_id"

        @JvmField
        val USER_ID: String = "user_id"

        @JvmField
        val SUB: String = "sub"

        @JvmField
        val EXP: String = "exp"

        @JvmField
        val EXPIRES_AT: String = "expires_at"

        @JvmField
        val SCOPE_SEPARATOR: String = " "

        @JvmField
        val SCOPE: String = "scope"

        @JvmField
        val ACTIVE: String = "active"

        @JvmField
        val dateFormat: DateFormatter = DateFormatter(SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ"))
    }
}
