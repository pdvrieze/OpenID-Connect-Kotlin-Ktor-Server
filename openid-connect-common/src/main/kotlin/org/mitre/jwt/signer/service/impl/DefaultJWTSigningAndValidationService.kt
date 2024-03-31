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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.signer.service.JWTSigningAndValidationService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.util.*

class DefaultJWTSigningAndValidationService : JWTSigningAndValidationService {
    // map of identifier to signer
    private val signers: MutableMap<String, JWSSigner> = HashMap()

    // map of identifier to verifier
    private val verifiers: MutableMap<String, JWSVerifier> = HashMap()

    /**
     * the defaultSignerKeyId
     */
    override var defaultSignerKeyId: String? = null

    override var defaultSigningAlgorithm: JWSAlgorithm? = null
        private set

    // map of identifier to key
    private var keys: MutableMap<String, JWK> = HashMap()

    /**
     * Build this service based on the keys given. All public keys will be used
     * to make verifiers, all private keys will be used to make signers.
     *
     * A map of key identifier to key
     *
     * @throws InvalidKeySpecException If the keys in the JWKs are not valid
     * @throws NoSuchAlgorithmException If there is no appropriate algorithm to tie the keys to.
     */
    @Throws(InvalidKeySpecException::class, NoSuchAlgorithmException::class)
    constructor(keys: Map<String, JWK>) {
        this.keys = keys.toMutableMap()
        buildSignersAndVerifiers()
    }

    /**
     * Build this service based on the given keystore. All keys must have a key
     * id (`kid`) field in order to be used.
     *
     * @param keyStore the keystore to load all keys from
     *
     * @throws InvalidKeySpecException If the keys in the JWKs are not valid
     * @throws NoSuchAlgorithmException If there is no appropriate algorithm to tie the keys to.
     */
    constructor(keyStore: JWKSetKeyStore?) {
        // convert all keys in the keystore to a map based on key id
        if (keyStore?.jwkSet != null) {
            for (key in keyStore.keys) {
                if (!key.keyID.isNullOrEmpty()) {
                    // use the key ID that's built into the key itself
                    keys[key.keyID] = key
                } else {
                    // create a random key id
                    val fakeKid = UUID.randomUUID().toString()
                    keys[fakeKid] = key
                }
            }
        }
        buildSignersAndVerifiers()
    }


    var defaultSigningAlgorithmName: String?
        get() = defaultSigningAlgorithm?.name
        set(value) {
            defaultSigningAlgorithm = JWSAlgorithm.parse(value)
        }

    /**
     * Build all of the signers and verifiers for this based on the key map.
     * @throws InvalidKeySpecException If the keys in the JWKs are not valid
     * @throws NoSuchAlgorithmException If there is no appropriate algorithm to tie the keys to.
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun buildSignersAndVerifiers() {
        for ((id, jwk) in keys) {
            try {
                when (jwk) {
                    is RSAKey -> {
                        // build RSA signers & verifiers

                        if (jwk.isPrivate()) { // only add the signer if there's a private key
                            val signer = RSASSASigner(jwk)
                            signers[id] = signer
                        }

                        val verifier = RSASSAVerifier(jwk)
                        verifiers[id] = verifier
                    }

                    is ECKey -> {
                        // build EC signers & verifiers

                        if (jwk.isPrivate()) {
                            val signer = ECDSASigner(jwk)
                            signers[id] = signer
                        }

                        val verifier = ECDSAVerifier(jwk)
                        verifiers[id] = verifier
                    }

                    is OctetSequenceKey -> {
                        // build HMAC signers & verifiers

                        if (jwk.isPrivate()) { // technically redundant check because all HMAC keys are private
                            val signer = MACSigner(jwk)
                            signers[id] = signer
                        }

                        val verifier = MACVerifier(jwk)
                        verifiers[id] = verifier
                    }

                    else -> {
                        logger.warn("Unknown key type: $jwk")
                    }
                }
            } catch (e: JOSEException) {
                logger.warn("Exception loading signer/verifier", e)
            }
        }

        if (defaultSignerKeyId == null && keys.size == 1) {
            // if there's only one key, it's the default
            defaultSignerKeyId = keys.keys.single()
        }
    }

    /**
     * Sign a jwt in place using the configured default signer.
     */
    override fun signJwt(jwt: SignedJWT) {
        checkNotNull(defaultSignerKeyId) { "Tried to call default signing with no default signer ID set" }

        val signer = signers[defaultSignerKeyId]

        try {
            jwt.sign(signer)
        } catch (e: JOSEException) {
            logger.error("Failed to sign JWT, error was: ", e)
        }
    }

    override fun signJwt(jwt: SignedJWT, alg: JWSAlgorithm) {
        val signer: JWSSigner? = signers.values.firstOrNull { it.supportedJWSAlgorithms().contains(alg) }

        if (signer == null) {
            //If we can't find an algorithm that matches, we can't sign
            logger.error("No matching algirthm found for alg=$alg")
            return
        }

        try {
            jwt.sign(signer)
        } catch (e: JOSEException) {
            logger.error("Failed to sign JWT, error was: ", e)
        }
    }

    override fun validateSignature(jwt: SignedJWT): Boolean {
        return verifiers.values.any { verifier ->
            try {
                jwt.verify(verifier)
            } catch (e: JOSEException) {
                logger.error("Failed to validate signature with " + verifier + " error message: " + e.message)
                false
            }
        }
    }

    override val allPublicKeys: Map<String, JWK>
        get() {
            return keys.mapNotNull { (k, v) -> v.toPublicJWK()?.let { k to it } }.associateTo(HashMap()) { it }
        }

        /* (non-Javadoc)
	 * @see org.mitre.jwt.signer.service.JwtSigningAndValidationService#getAllSigningAlgsSupported()
	 */
    override val allSigningAlgsSupported: Collection<JWSAlgorithm>
        get() {
            return (signers.values.asSequence() + verifiers.values.asSequence()).flatMapTo(HashSet()) { it.supportedJWSAlgorithms() }
        }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DefaultJWTSigningAndValidationService::class.java)
    }
}
