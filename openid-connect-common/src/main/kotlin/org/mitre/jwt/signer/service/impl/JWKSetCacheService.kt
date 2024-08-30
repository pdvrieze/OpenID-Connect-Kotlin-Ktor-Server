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
package org.mitre.jwt.signer.service.impl

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.utils.io.errors.*
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.util.getLogger
import java.text.ParseException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 *
 * Creates a caching map of JOSE signers/validators and encrypters/decryptors
 * keyed on the JWK Set URI. Dynamically loads JWK Sets to create the services.
 *
 * @author jricher
 */
class JWKSetCacheService {
    // map of jwk set uri -> signing/validation service built on the keys found in that jwk set
    private val validators: LoadingCache<String, JWTSigningAndValidationService> =
        CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetVerifierFetcher(HttpClientBuilder.create().useSystemProperties().build()))

    // map of jwk set uri -> encryption/decryption service built on the keys found in that jwk set
    private val encrypters: LoadingCache<String, JWTEncryptionAndDecryptionService> =
        CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetEncryptorFetcher(HttpClientBuilder.create().useSystemProperties().build()))

    /**
     * @throws ExecutionException
     * @see com.google.common.cache.Cache.get
     */
    fun getValidator(jwksUri: String): JWTSigningAndValidationService? {
        try {
            return validators.get(jwksUri)
        } catch (e: UncheckedExecutionException) {
            logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.message)
            return null
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.message)
            return null
        }
    }

    fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService? {
        try {
            return encrypters[jwksUri]
        } catch (e: UncheckedExecutionException) {
            logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.message)
            return null
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.message)
            return null
        }
    }

    /**
     * @author jricher
     */
    private inner class JWKSetVerifierFetcher(httpClient: HttpClient) : CacheLoader<String, JWTSigningAndValidationService>() {
//        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
//        private val restTemplate = RestTemplate(httpFactory)

        /**
         * Load the JWK Set and build the appropriate signing service.
         */
        @Throws(Exception::class)
        override fun load(keyUrl: String): JWTSigningAndValidationService {
            val jsonString: String? = TODO() //restTemplate.getForObject(keyUrl, String::class.java)
            val jwkSet = JWKSet.parse(jsonString)

            val keyStore = JWKSetKeyStore(jwkSet)

            val service: JWTSigningAndValidationService = DefaultJWTSigningAndValidationService(keyStore)

            return service
        }
    }

    /**
     * @author jricher
     */
    private inner class JWKSetEncryptorFetcher(httpClient: HttpClient) :
        CacheLoader<String, JWTEncryptionAndDecryptionService>() {
//        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
//        private val restTemplate = RestTemplate(httpFactory)

        /* (non-Javadoc)
		 * @see com.google.common.cache.CacheLoader#load(java.lang.Object)
		 */
        override fun load(key: String): JWTEncryptionAndDecryptionService {
            try {
                val jsonString: String = TODO() //restTemplate.getForObject(key, String::class.java)
                val jwkSet = JWKSet.parse(jsonString)

                val keyStore = JWKSetKeyStore(jwkSet)

                val service: JWTEncryptionAndDecryptionService = DefaultJWTEncryptionAndDecryptionService(keyStore)

                return service
            } catch (e: ParseException) {
                throw IllegalArgumentException("Unable to load JWK Set")
            } catch (e: IOException) {
                throw IllegalArgumentException("Unable to load JWK Set")
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<JWKSetCacheService>()
    }
}
