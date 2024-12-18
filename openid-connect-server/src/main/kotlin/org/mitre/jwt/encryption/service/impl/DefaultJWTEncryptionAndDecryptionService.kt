package org.mitre.jwt.encryption.service.impl

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEEncrypter
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService
import org.mitre.util.getLogger
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException

/**
 * @author wkim
 */
class DefaultJWTEncryptionAndDecryptionService : JWTEncryptionAndDecryptionService {
    // map of identifier to encrypter
    private val encrypters: MutableMap<String, JWEEncrypter> = HashMap()

    // map of identifier to decrypter
    private val decrypters: MutableMap<String, JWEDecrypter> = HashMap()

    var defaultEncryptionKeyId: String? = null
        get() = field ?: keys.keys.singleOrNull()

    var defaultDecryptionKeyId: String? = null
        get() = field ?: keys.keys.singleOrNull()

    @JvmField
	var defaultAlgorithm: JWEAlgorithm? = null

    // map of identifier to key
    private var keys: MutableMap<String, JWK> = HashMap()

    /**
     * Build this service based on the keys given. All public keys will be used to make encrypters,
     * all private keys will be used to make decrypters.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws JOSEException
     */
    constructor(keys: Map<String, JWK>) {
        this.keys = keys.toMutableMap()
        buildEncryptersAndDecrypters()
    }

    /**
     * Build this service based on the given keystore. All keys must have a key
     * id (`kid`) field in order to be used.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws JOSEException
     */
    constructor(keyStore: JWKSetKeyStore) {
        // convert all keys in the keystore to a map based on key id

        for (key in keyStore.keys) {
            if (!key.keyID.isNullOrEmpty()) {
                keys[key.keyID] = key
            } else {
                throw IllegalArgumentException("Tried to load a key from a keystore without a 'kid' field: $key")
            }
        }

        buildEncryptersAndDecrypters()
    }

    fun afterPropertiesSet() {
        requireNotNull(keys) { "Encryption and decryption service must have at least one key configured." }
        try {
            buildEncryptersAndDecrypters()
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Encryption and decryption service could not find given algorithm.")
        } catch (e: InvalidKeySpecException) {
            throw IllegalArgumentException("Encryption and decryption service saw an invalid key specification.")
        } catch (e: JOSEException) {
            throw IllegalArgumentException("Encryption and decryption service was unable to process JOSE object.")
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.jwt.encryption.service.JwtEncryptionAndDecryptionService#encryptJwt(com.nimbusds.jwt.EncryptedJWT)
	 */
    override fun encryptJwt(jwt: JWEObject) {
        checkNotNull(defaultEncryptionKeyId) { "Tried to call default encryption with no default encrypter ID set" }

        val encrypter = encrypters[defaultEncryptionKeyId]

        try {
            jwt.encrypt(encrypter)
        } catch (e: JOSEException) {
            logger.error("Failed to encrypt JWT, error was: ", e)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.jwt.encryption.service.JwtEncryptionAndDecryptionService#decryptJwt(com.nimbusds.jwt.EncryptedJWT)
	 */
    override fun decryptJwt(jwt: JWEObject) {
        checkNotNull(defaultDecryptionKeyId) { "Tried to call default decryption with no default decrypter ID set" }

        val decrypter = decrypters[defaultDecryptionKeyId]

        try {
            jwt.decrypt(decrypter)
        } catch (e: JOSEException) {
            logger.error("Failed to decrypt JWT, error was: ", e)
        }
    }

    /**
     * Builds all the encrypters and decrypters for this service based on the key map.
     * @throws
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws JOSEException
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class, JOSEException::class)
    private fun buildEncryptersAndDecrypters() {
        for ((id, jwk) in keys) {
            if (jwk is RSAKey) {
                // build RSA encrypters and decrypters

                val encrypter = RSAEncrypter(jwk) // there should always at least be the public key
                encrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                encrypters[id] = encrypter

                if (jwk.isPrivate()) { // we can decrypt!
                    val decrypter = RSADecrypter(jwk)
                    decrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                    decrypters[id] = decrypter
                } else {
                    logger.warn("No private key for key #" + jwk.getKeyID())
                }
            } else if (jwk is ECKey) {
                // build EC Encrypters and decrypters

                val encrypter = ECDHEncrypter(jwk)
                encrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                encrypters[id] = encrypter

                if (jwk.isPrivate()) { // we can decrypt too
                    val decrypter = ECDHDecrypter(jwk)
                    decrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                    decrypters[id] = decrypter
                } else {
                    logger.warn("No private key for key # " + jwk.getKeyID())
                }
            } else if (jwk is OctetSequenceKey) {
                // build symmetric encrypters and decrypters

                val encrypter = DirectEncrypter(jwk)
                encrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
                val decrypter = DirectDecrypter(jwk)
                decrypter.jcaContext.provider = BouncyCastleProviderSingleton.getInstance()

                encrypters[id] = encrypter
                decrypters[id] = decrypter
            } else {
                logger.warn("Unknown key type: $jwk")
            }
        }
    }

    override val allPublicKeys: Map<String, JWK>
        get() {
            return keys.map { (k, v) -> k to v.toPublicJWK()}
                .filter { (k,v) -> v!=null }
                .associateTo(HashMap()) { it }
        }

    override val allEncryptionAlgsSupported: Collection<JWEAlgorithm>
        get() {
            return (encrypters.values.asSequence() + decrypters.values.asSequence()).flatMapTo(HashSet()) {
                it.supportedJWEAlgorithms()
            }
        }

        /* (non-Javadoc)
	 * @see org.mitre.jwt.encryption.service.JwtEncryptionAndDecryptionService#getAllEncryptionEncsSupported()
	 */
    override val allEncryptionEncsSupported: Collection<EncryptionMethod>
        get() {
            return (encrypters.values.asSequence() + decrypters.values.asSequence()).flatMapTo(HashSet()) {
                it.supportedEncryptionMethods()
            }
        }


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<DefaultJWTEncryptionAndDecryptionService>()
    }
}
