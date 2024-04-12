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
package org.mitre.oauth2.introspectingfilter

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.*

class TestOAuth2AccessTokenImpl {
    @Test
    fun testFullToken() {
        val tokenObj = buildJsonObject {
            put("active", true)
            put("scope", scopeString)
            put("exp", expVal)
            put("sub", "subject")
            put("client_id", "123-456-789")
        }


        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(scopes, tok.scope)
        assertEquals(exp, tok.expiration)
    }

    @Test
    fun testNullExp() {
        val tokenObj = buildJsonObject {
            put("active", true)
            put("scope", scopeString)
            put("sub", "subject")
            put("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(scopes, tok.scope)
        assertEquals(null, tok.expiration)
    }

    @Test
    fun testNullScopes() {
        val tokenObj = JsonObject(mapOf(
            "active" to JsonPrimitive(true),
            "exp" to JsonPrimitive(expVal),
            "sub" to JsonPrimitive("subject"),
            "client_id" to JsonPrimitive("123-456-789"),
        ))

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(Collections.EMPTY_SET, tok.scope)
        assertEquals(exp, tok.expiration)
    }

    @Test
    fun testNullScopesNullExp() {
        val tokenObj = buildJsonObject {
            put("active", true)
            put("sub", "subject")
            put("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(Collections.EMPTY_SET, tok.scope)
        assertEquals(null, tok.expiration)
    }

    companion object {
        private const val tokenString = "thisisatokenstring"

        private val scopes: Set<String> = setOf("bar", "foo")
        private const val scopeString = "foo bar"

        private val exp = Date(123 * 1000L)
        private const val expVal = 123L
    }
}
