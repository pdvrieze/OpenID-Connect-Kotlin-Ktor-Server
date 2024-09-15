package org.mitre.jwt.signer.service

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService

interface JWKSetCacheService {
    fun getValidator(jwksUri: String): JWTSigningAndValidationService?

    fun getEncrypter(jwksUri: String): JWTEncryptionAndDecryptionService?
}
