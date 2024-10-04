package org.mitre.jwt.signer.service

import com.nimbusds.jose.JWSAlgorithm
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.oauth2.model.OAuthClientDetails

interface ClientKeyCacheService {
    suspend fun getValidator(client: OAuthClientDetails, alg: JWSAlgorithm): JWTSigningAndValidationService?
    suspend fun getEncrypter(client: OAuthClientDetails): JWTEncryptionAndDecryptionService?
}
