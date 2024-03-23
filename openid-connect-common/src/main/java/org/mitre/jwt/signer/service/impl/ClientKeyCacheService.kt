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
package org.mitre.jwt.signer.service.impl

import com.google.common.base.Strings
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.ClientDetailsEntity
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 *
 * Takes in a client and returns the appropriate validator or encrypter for
 * that client's registered key types.
 *
 * @author jricher
 */
@Service
class ClientKeyCacheService {
    @Autowired
    private val jwksUriCache = JWKSetCacheService()

    @Autowired
    private val symmetricCache = SymmetricKeyJWTValidatorCacheService()

    // cache of validators for by-value JWKs
    private val jwksValidators: LoadingCache<JWKSet, JWTSigningAndValidationService>

    // cache of encryptors for by-value JWKs
    private val jwksEncrypters: LoadingCache<JWKSet, JWTEncryptionAndDecryptionService>

    init {
        this.jwksValidators = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetVerifierBuilder())
        this.jwksEncrypters = CacheBuilder.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetEncryptorBuilder())
    }


    fun getValidator(client: ClientDetailsEntity, alg: JWSAlgorithm): JWTSigningAndValidationService? {
        try {
            return when (alg) {
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512 -> {
                    // asymmetric key

                    client.jwks?.let { jwksValidators[it] }
                        ?: client.jwksUri?.takeIf { it.isNotEmpty() }?.let { jwksUriCache.getValidator(it) }
                }
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512 -> {
                    // symmetric key

                    symmetricCache.getSymmetricValidtor(client)
                }
                else -> null
            }
        } catch (e: UncheckedExecutionException) {
            logger.error("Problem loading client validator", e)
            return null
        } catch (e: ExecutionException) {
            logger.error("Problem loading client validator", e)
            return null
        }
    }

    fun getEncrypter(client: ClientDetailsEntity): JWTEncryptionAndDecryptionService? {
        try {
            return client.jwks?.let { jwksEncrypters[it] }
                ?: client.jwksUri?.takeIf { it.isNotEmpty() }?.let { jwksUriCache.getEncrypter(it) }
        } catch (e: UncheckedExecutionException) {
            logger.error("Problem loading client encrypter", e)
            return null
        } catch (e: ExecutionException) {
            logger.error("Problem loading client encrypter", e)
            return null
        }
    }


    private inner class JWKSetEncryptorBuilder : CacheLoader<JWKSet, JWTEncryptionAndDecryptionService>() {
        @Throws(Exception::class)
        override fun load(key: JWKSet): JWTEncryptionAndDecryptionService {
            return DefaultJWTEncryptionAndDecryptionService(JWKSetKeyStore(key))
        }
    }

    private inner class JWKSetVerifierBuilder : CacheLoader<JWKSet, JWTSigningAndValidationService>() {
        @Throws(Exception::class)
        override fun load(key: JWKSet): JWTSigningAndValidationService {
            return DefaultJWTSigningAndValidationService(JWKSetKeyStore(key))
        }
    }


    companion object {
        private val logger: Logger = LoggerFactory.getLogger(ClientKeyCacheService::class.java)
    }
}
