package org.mitre.jwt.signer.service.impl.ktor

import com.nimbusds.jose.jwk.JWKSet
import io.github.pdvrieze.oidc.util.CoroutineCache
import io.github.pdvrieze.oidc.util.expireAfterWrite
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService
import org.mitre.jwt.signer.service.JWKSetCacheService
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService
import org.mitre.util.getLogger
import java.util.concurrent.ExecutionException
import kotlin.time.Duration.Companion.hours

/**
 *
 * Creates a caching map of JOSE signers/validators and encrypters/decryptors
 * keyed on the JWK Set URI. Dynamically loads JWK Sets to create the services.
 *
 * @author jricher
 */
class KtorJWKSetCacheService(private val httpClient: HttpClient = HttpClient(Java)) : JWKSetCacheService {
    // map of jwk set uri -> signing/validation service built on the keys found in that jwk set
    private val validators =
        CoroutineCache(::fetchJwkSet) {
            expireAfterWrite(1.hours)
            maximumSize(100)
        }

    // map of jwk set uri -> encryption/decryption service built on the keys found in that jwk set
    private val encrypters = CoroutineCache(::fetchSetEncryptor) {
        expireAfterWrite(1.hours)
        maximumSize(100)
    }

    override suspend fun getValidator(jwksUri: String): JWTSigningAndValidationService? {
        try {
            return validators.load(jwksUri)
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from $jwksUri: ${e.message}")
            return null
        }
    }

    override suspend fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService? {
        try {
            return encrypters.load(jwksUri)
        } catch (e: ExecutionException) {
            logger.warn("Couldn't load JWK Set from $jwksUri: ${e.message}")
            return null
        }
    }

    private suspend fun fetchJwkSet(keyUrl: String): JWTSigningAndValidationService {
        val response = httpClient.get(keyUrl)
        if (!response.status.isSuccess()) { throw IllegalArgumentException("Could not load jwk set from $keyUrl: ${response.status}") }

        val jwkSet = JWKSet.parse(response.bodyAsText())

        val keyStore = JWKSetKeyStore(jwkSet)
        val defaultKeyId = requireNotNull(jwkSet.keys.firstOrNull(), { "Missing key" }).keyID

        val service: JWTSigningAndValidationService = DefaultJWTSigningAndValidationService(keyStore, defaultKeyId)

        return service
    }

    private suspend fun fetchSetEncryptor(url: String): JWTEncryptionAndDecryptionService {
        val response = httpClient.get(url)
        if (!response.status.isSuccess()) {
            throw IllegalArgumentException("Could not load key from $url: ${response.status}")
        }

        val jwkSet = JWKSet.parse(response.bodyAsText())
        val keyStore = JWKSetKeyStore(jwkSet)

        return DefaultJWTEncryptionAndDecryptionService(keyStore)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<JWKSetCacheService>()
    }
}
