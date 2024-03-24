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
/**
 *
 */
package org.mitre.jose.keystore

import com.google.common.base.Charsets
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import org.springframework.core.io.Resource
import java.io.IOException
import java.io.InputStreamReader
import java.text.ParseException

/**
 * @author jricher
 */
class JWKSetKeyStore() {

    var jwkSet: JWKSet? = null
        set(value) {
            field = value
            initializeJwkSet()
        }

    var location: Resource? = null
        set(value) {
            field = value
            initializeJwkSet()
        }

    constructor(jwkSet: JWKSet) : this() {
        this.jwkSet = jwkSet
    }

    private fun initializeJwkSet(): JWKSet = when (val j = jwkSet) {
        null -> {
            val location = requireNotNull(location) { "Key store must be initialized with at least one of a jwkSet or a location." }
            require(location.exists() && location.isReadable) { "Key Set resource could not be read: $location" }
            try {
                // read in the file from disk
                val s = InputStreamReader(location.inputStream, Charsets.UTF_8).readText()

                // parse it into a jwkSet object
                JWKSet.parse(s).also { jwkSet = it }
            } catch (e: IOException) {
                throw IllegalArgumentException("Key Set resource could not be read: $location")
            } catch (e: ParseException) {
                throw IllegalArgumentException("Key Set resource could not be parsed: $location")
            }
        }
        else -> j
    }

    /**
     * Get the list of keys in this keystore. This is a passthrough to the underlying JWK Set
     */
    val keys: List<JWK>
        get() = (jwkSet ?: initializeJwkSet()).keys
}
