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
package org.mitre.jwt.signer.service

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT

interface JWTSigningAndValidationService {
    /**
     * Get all public keys for this service, mapped by their Key ID
     */
    val allPublicKeys: Map<String, JWK>

    /**
     * Checks the signature of the given JWT against all configured signers,
     * returns true if at least one of the signers validates it.
     *
     * @param jwtString
     * the string representation of the JWT as sent on the wire
     * @return true if the signature is valid, false if not
     * @throws NoSuchAlgorithmException
     */
    fun validateSignature(jwtString: SignedJWT): Boolean

    /**
     * Called to sign a jwt in place for a client that hasn't registered a preferred signing algorithm.
     * Use the default algorithm to sign.
     *
     * @param jwt the jwt to sign
     * @return the signed jwt
     * @throws NoSuchAlgorithmException
     */
    fun signJwt(jwt: SignedJWT)

    /**
     * Get the default signing algorithm for use when nothing else has been specified.
     * @return
     */
    val defaultSigningAlgorithm: JWSAlgorithm?

    /**
     * Get the list of all signing algorithms supported by this service.
     * @return
     */
    val allSigningAlgsSupported: Collection<JWSAlgorithm>

    /**
     * Sign a jwt using the selected algorithm. The algorithm is selected using the String parameter values specified
     * in the JWT spec, section 6. I.E., "HS256" means HMAC with SHA-256 and corresponds to our HmacSigner class.
     *
     * @param jwt the jwt to sign
     * @param alg the name of the algorithm to use, as specified in JWS s.6
     * @return the signed jwt
     */
    fun signJwt(jwt: SignedJWT, alg: JWSAlgorithm)

    val defaultSignerKeyId: String?
    /**
     * TODO: method to sign a jwt using a specified algorithm and a key id
     */
}
