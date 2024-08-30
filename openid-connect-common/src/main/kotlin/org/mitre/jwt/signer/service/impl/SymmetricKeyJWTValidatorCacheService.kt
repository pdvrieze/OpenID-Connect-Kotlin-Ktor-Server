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

import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.util.Base64URL
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.util.getLogger
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/**
 * Creates and caches symmetrical validators for clients based on client secrets.
 *
 * @author jricher
 */
class SymmetricKeyJWTValidatorCacheService {
    private val validators: LoadingCache<String, JWTSigningAndValidationService> = CacheBuilder.newBuilder()
        .expireAfterAccess(24, TimeUnit.HOURS)
        .maximumSize(100)
        .build(SymmetricValidatorBuilder())

    /**
     * Create a symmetric signing and validation service for the given client
     *
     */
    fun getSymmetricValidator(client: OAuthClientDetails): JWTSigningAndValidationService? {
        if (client.getClientSecret().isNullOrEmpty()) {
            logger.error("Couldn't create symmetric validator for client ${client.getClientId()} without a client secret")
            return null
        }

        try {
            return validators[client.getClientSecret()]
        } catch (ue: UncheckedExecutionException) {
            logger.error("Problem loading client validator", ue)
            return null
        } catch (e: ExecutionException) {
            logger.error("Problem loading client validator", e)
            return null
        }
    }

    inner class SymmetricValidatorBuilder : CacheLoader<String, JWTSigningAndValidationService>() {
        @Throws(Exception::class)
        override fun load(key: String): JWTSigningAndValidationService {
            try {
                val id = "SYMMETRIC-KEY"
                val jwk: JWK = OctetSequenceKey.Builder(Base64URL.encode(key))
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(id)
                    .build()
                val keys: Map<String, JWK> = mapOf(id to jwk)
                val service: JWTSigningAndValidationService = DefaultJWTSigningAndValidationService(keys)

                return service
            } catch (e: NoSuchAlgorithmException) {
                logger.error("Couldn't create symmetric validator for client", e)
            } catch (e: InvalidKeySpecException) {
                logger.error("Couldn't create symmetric validator for client", e)
            }

            throw IllegalArgumentException("Couldn't create symmetric validator for client")
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<SymmetricKeyJWTValidatorCacheService>()
    }
}
