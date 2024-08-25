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

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.mitre.util.asString
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import java.util.*
import java.util.concurrent.TimeUnit

class OAuth2AccessTokenImpl(introspectionResponse: JsonObject, tokenString: String) : OAuth2AccessToken {
    var introspectionResponse: JsonObject? = null
    private val tokenString: String
    private var scopes: Set<String> = HashSet()
    private var expireDate: Date? = null


    init {
        this.introspectionResponse = introspectionResponse
        this.tokenString = tokenString
        if (introspectionResponse["scope"] != null) {
            scopes = introspectionResponse["scope"].asString().splitToSequence(' ').toHashSet()
        }

        if (introspectionResponse["exp"] != null) {
            expireDate = Date(introspectionResponse["exp"]!!.jsonPrimitive.long * 1000L)
        }
    }


    override fun getAdditionalInformation(): Map<String, Any>? {
        return null
    }

    override fun getScope(): Set<String> {
        return scopes
    }

    override fun getRefreshToken(): OAuth2RefreshToken? {
        return null
    }

    override fun getTokenType(): String {
        return OAuth2AccessToken.BEARER_TYPE
    }

    override fun isExpired(): Boolean {
        return expireDate?.before(Date()) == true
    }

    override fun getExpiration(): Date? {
        return expireDate
    }

    override fun getExpiresIn(): Int {
        return expireDate?.let {
            TimeUnit.MILLISECONDS.toSeconds(it.time - Date().time).toInt()
        } ?: 0
    }

    override fun getValue(): String {
        return tokenString
    }
}
