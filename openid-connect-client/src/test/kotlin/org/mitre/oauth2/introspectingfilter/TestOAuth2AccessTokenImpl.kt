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

import com.google.common.collect.ImmutableSet
import com.google.gson.JsonObject
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Test
import java.util.*

class TestOAuth2AccessTokenImpl {
    @Test
    fun testFullToken() {
        val tokenObj = JsonObject().apply {
            addProperty("active", true)
            addProperty("scope", scopeString)
            addProperty("exp", expVal)
            addProperty("sub", "subject")
            addProperty("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertThat(tok.scope, CoreMatchers.`is`(CoreMatchers.equalTo(scopes)))
        assertThat(tok.expiration, CoreMatchers.`is`(CoreMatchers.equalTo(exp)))
    }

    @Test
    fun testNullExp() {
        val tokenObj = JsonObject().apply {
            addProperty("active", true)
            addProperty("scope", scopeString)
            addProperty("sub", "subject")
            addProperty("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertThat(tok.scope, CoreMatchers.`is`(CoreMatchers.equalTo(scopes)))
        assertThat(tok.expiration, CoreMatchers.`is`(CoreMatchers.equalTo(null)))
    }

    @Test
    fun testNullScopes() {
        val tokenObj = JsonObject().apply {
            addProperty("active", true)
            addProperty("exp", expVal)
            addProperty("sub", "subject")
            addProperty("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertThat(tok.scope, CoreMatchers.`is`(CoreMatchers.equalTo(Collections.EMPTY_SET)))
        assertThat(tok.expiration, CoreMatchers.`is`(CoreMatchers.equalTo(exp)))
    }

    @Test
    fun testNullScopesNullExp() {
        val tokenObj = JsonObject().apply {
            addProperty("active", true)
            addProperty("sub", "subject")
            addProperty("client_id", "123-456-789")
        }

        val tok = OAuth2AccessTokenImpl(tokenObj, tokenString)

        assertThat(tok.scope, CoreMatchers.`is`(CoreMatchers.equalTo(Collections.EMPTY_SET)))
        assertThat(tok.expiration, CoreMatchers.`is`(CoreMatchers.equalTo(null)))
    }

    companion object {
        private const val tokenString = "thisisatokenstring"

        private val scopes: Set<String> = ImmutableSet.of("bar", "foo")
        private const val scopeString = "foo bar"

        private val exp = Date(123 * 1000L)
        private const val expVal = 123L
    }
}
