package org.mitre.jwt.signer.service

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService

interface JWKSetCacheService {
    suspend fun getValidator(jwksUri: String): JWTSigningAndValidationService?

    suspend fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService?
}
