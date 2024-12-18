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
import java.time.Instant
import java.util.*

class TestOAuth2AccessTokenImpl {
    @Test
    fun testFullToken() {
        val tokenObj = IntrospectionResponse (
            active = true,
            scopeString= scopeString,
            expiration = Instant.ofEpochSecond(expVal),
            subject = "subject",
            clientId= "123-456-789",
        )


        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(scopes, tok.scope)
        assertEquals(exp, tok.expirationInstant)
    }

    @Test
    fun testMinExp() {

        val tokenObj = IntrospectionResponse (
            active = true,
            scopeString= scopeString,
            subject = "subject",
            clientId= "123-456-789",
        )

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(scopes, tok.scope)
        assertEquals(Instant.MIN, tok.expirationInstant)
    }

    @Test
    fun testNullScopes() {
        val tokenObj = IntrospectionResponse (
            active = true,
            expiration = Instant.ofEpochSecond(expVal),
            subject = "subject",
            clientId= "123-456-789",
        )
        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(Collections.EMPTY_SET, tok.scope)
        assertEquals(exp, tok.expirationInstant)
    }

    @Test
    fun testNullScopesMinExp() {
        val tokenObj = IntrospectionResponse (
            active = true,
            subject = "subject",
            clientId= "123-456-789",
        )

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertEquals(emptySet<String>(), tok.scope)
        assertEquals(Instant.MIN, tok.expirationInstant)
    }

    companion object {
        private const val tokenString = "thisisatokenstring"

        private val scopes: Set<String> = setOf("bar", "foo")
        private const val scopeString = "foo bar"

        private val exp = Instant.ofEpochSecond(123)
        private const val expVal = 123L
    }
}
