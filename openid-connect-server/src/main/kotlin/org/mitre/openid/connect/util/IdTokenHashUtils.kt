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
package org.mitre.openid.connect.util

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.util.getLogger
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * Utility class for generating hashes for access tokens and authorization codes
 * to be included in an ID Token.
 *
 * @author Amanda Anganes
 */
object IdTokenHashUtils {
    /**
     * Logger for this class
     */
    private val logger = getLogger<IdTokenHashUtils>()

    /**
     * Compute the SHA hash of an authorization code
     */
    @JvmStatic
    fun getCodeHash(signingAlg: JWSAlgorithm, code: String): Base64URL? {
        return getHash(signingAlg, code.toByteArray())
    }

    /**
     * Compute the SHA hash of a token
     */
    @JvmStatic
    fun getAccessTokenHash(signingAlg: JWSAlgorithm, token: OAuth2AccessToken): Base64URL? {
        return getAccessTokenHash(signingAlg, token.jwt)
    }

    /**
     * Compute the SHA hash of a token
     */
    @JvmStatic
    fun getAccessTokenHash(signingAlg: JWSAlgorithm, token: OAuth2AccessToken.Builder): Base64URL? {
        return getAccessTokenHash(signingAlg, token.jwt!!)
    }

    private fun getAccessTokenHash(
        signingAlg: JWSAlgorithm,
        jwt: JWT
    ): Base64URL? {
        val tokenBytes = jwt.serialize().toByteArray()

        return getHash(signingAlg, tokenBytes)
    }

    fun getHash(signingAlg: JWSAlgorithm, bytes: ByteArray): Base64URL? {
        //Switch based on the given signing algorithm - use SHA-xxx with the same 'xxx' bitnumber
        //as the JWSAlgorithm to hash the token.

        val hashAlg = when (signingAlg) {
            JWSAlgorithm.HS256, JWSAlgorithm.ES256, JWSAlgorithm.RS256, JWSAlgorithm.PS256 -> "SHA-256"
            JWSAlgorithm.ES384, JWSAlgorithm.HS384, JWSAlgorithm.RS384, JWSAlgorithm.PS384 -> "SHA-384"
            JWSAlgorithm.ES512, JWSAlgorithm.HS512, JWSAlgorithm.RS512, JWSAlgorithm.PS512 -> "SHA-512"
            else -> return null
        }

        try {
            val hasher = MessageDigest.getInstance(hashAlg)
            hasher.reset()
            hasher.update(bytes)

            val hashBytes = hasher.digest()
            val hashBytesLeftHalf = hashBytes.copyOf(hashBytes.size / 2)
            val encodedHash = Base64URL.encode(hashBytesLeftHalf)

            return encodedHash
        } catch (e: NoSuchAlgorithmException) {
            logger.error("No such algorithm error: ", e)
            return null
        }
    }
}
