package org.mitre.jwt.signer.service.impl

import com.github.benmanes.caffeine.cache.CacheLoader
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.ClientKeyCacheService
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.util.getLogger
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit


/**
 *
 * Takes in a client and returns the appropriate validator or encrypter for
 * that client's registered key types.
 *
 * @author jricher
 */
class DefaultClientKeyCacheService(
    private val jwksUriCache: JWKSetCacheService
) : ClientKeyCacheService {

    private val symmetricCache = SymmetricKeyJWTValidatorCacheService()

    // cache of validators for by-value JWKs
    private val jwksValidators: LoadingCache<JWKSet, JWTSigningAndValidationService> = Caffeine.newBuilder()
        .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
        .maximumSize(100)
        .build(JWKSetVerifierBuilder())

    // cache of encryptors for by-value JWKs
    private val jwksEncrypters: LoadingCache<JWKSet, JWTEncryptionAndDecryptionService> = Caffeine.newBuilder()
        .expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
        .maximumSize(100)
        .build(JWKSetEncryptorBuilder())

    override suspend fun getValidator(client: OAuthClientDetails, alg: JWSAlgorithm): JWTSigningAndValidationService? {
        try {
            return when (alg) {
                JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512,
                JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512
                    -> {
                    // asymmetric key

                    client.jwks?.let { jwksValidators[it] }
                        ?: client.jwksUri?.takeIf { it.isNotEmpty() }?.let { jwksUriCache.getValidator(it) }
                }
                JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512 -> {
                    // symmetric key

                    symmetricCache.getSymmetricValidator(client)
                }
                else -> null
            }
        } catch (e: ExecutionException) {
            logger.error("Problem loading client validator", e)
            return null
        }
    }

    override suspend fun getEncrypter(client: OAuthClientDetails): JWTEncryptionAndDecryptionService? {
        try {
            return client.jwks?.let { jwksEncrypters[it] }
                ?: client.jwksUri?.takeIf { it.isNotEmpty() }?.let { jwksUriCache.getEncrypter(it) }
        } catch (e: ExecutionException) {
            logger.error("Problem loading client encrypter", e)
            return null
        }
    }


    private inner class JWKSetEncryptorBuilder : CacheLoader<JWKSet, JWTEncryptionAndDecryptionService> {
        @Throws(Exception::class)
        override fun load(key: JWKSet): JWTEncryptionAndDecryptionService {
            return org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService(JWKSetKeyStore(key))
        }
    }

    private inner class JWKSetVerifierBuilder : CacheLoader<JWKSet, JWTSigningAndValidationService> {
        @Throws(Exception::class)
        override fun load(key: JWKSet): JWTSigningAndValidationService {
            return DefaultJWTSigningAndValidationService(JWKSetKeyStore(key))
        }
    }


    companion object {
        private val logger = getLogger<DefaultClientKeyCacheService>()
    }
}
