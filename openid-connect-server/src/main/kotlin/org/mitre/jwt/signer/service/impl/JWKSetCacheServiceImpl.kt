package org.mitre.jwt.signer.service.impl

import com.github.benmanes.caffeine.cache.CacheLoader
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import com.nimbusds.jose.jwk.JWKSet
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.util.getLogger
import java.io.IOException
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
class JWKSetCacheServiceImpl : JWKSetCacheService {
    // map of jwk set uri -> signing/validation service built on the keys found in that jwk set
    private val validators: LoadingCache<String, JWTSigningAndValidationService> =
        Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetVerifierFetcher(HttpClientBuilder.create().useSystemProperties().build()))

    // map of jwk set uri -> encryption/decryption service built on the keys found in that jwk set
    private val encrypters: LoadingCache<String, JWTEncryptionAndDecryptionService> =
        Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
            .maximumSize(100)
            .build(JWKSetEncryptorFetcher(HttpClientBuilder.create().useSystemProperties().build()))

    /**
     * @throws ExecutionException
     * @see com.google.common.cache.Cache.get
     */
    override suspend fun getValidator(jwksUri: String): JWTSigningAndValidationService? {
        try {
            return validators.get(jwksUri)
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from " + jwksUri + ": " + e.message)
            return null
        }
    }

    override suspend fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService? {
        try {
            return encrypters[jwksUri]
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from $jwksUri: ${e.message}")
            return null
        }
    }

    /**
     * @author jricher
     */
    private inner class JWKSetVerifierFetcher(httpClient: HttpClient) : CacheLoader<String, JWTSigningAndValidationService> {
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
        CacheLoader<String, JWTEncryptionAndDecryptionService> {
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

                val service = DefaultJWTEncryptionAndDecryptionService(keyStore)

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
