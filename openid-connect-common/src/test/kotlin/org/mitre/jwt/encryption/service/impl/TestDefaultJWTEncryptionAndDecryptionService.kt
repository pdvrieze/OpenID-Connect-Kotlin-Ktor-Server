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
package org.mitre.jwt.encryption.service.impl

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.jca.JCASupport
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mitre.jose.keystore.JWKSetKeyStore
import org.mitre.util.getLogger
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.text.ParseException
import java.util.*
import javax.crypto.Cipher

/**
 * @author wkim
 * @author tsitkov
 */
class TestDefaultJWTEncryptionAndDecryptionService {
    private val plainText = "The true sign of intelligence is not knowledge but imagination."

    private val issuer = "www.example.net"
    private val subject = "example_user"
    private lateinit var claimsSet: JWTClaimsSet

    // Example data taken from rfc7516 appendix A
    private val compactSerializedJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." +
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" +
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" +
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" +
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" +
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" +
            "6UklfCpIMfIjf7iGdXKHzg." +
            "48V1_ALb6US04U3b." +
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" +
            "SdiwkIr3ajwQzaBtQD_A." +
            "XFBoMYUZodetZdvTiFvSkQ"

    private val RSAkid = "rsa321"
    private val RSAjwk: JWK = RSAKey(
        Base64URL(
            "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
                    "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
                    "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
                    "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
                    "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
                    "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw"
        ),  // n
        Base64URL("AQAB"),  // e
        Base64URL(
            "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N" +
                    "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9" +
                    "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk" +
                    "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl" +
                    "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd" +
                    "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ"
        ),  // d
        KeyUse.ENCRYPTION, null, JWEAlgorithm.RSA_OAEP, RSAkid, null, null, null, null, null
    )

    private val RSAkid_2 = "rsa3210"
    private val RSAjwk_2: JWK = RSAKey(
        Base64URL(
            "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
                    "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
                    "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
                    "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
                    "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
                    "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw"
        ),  // n
        Base64URL("AQAB"),  // e
        Base64URL(
            "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N" +
                    "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9" +
                    "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk" +
                    "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl" +
                    "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd" +
                    "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ"
        ),  // d
        KeyUse.ENCRYPTION, null, JWEAlgorithm.RSA1_5, RSAkid_2, null, null, null, null, null
    )

    private val AESkid = "aes123"
    private val AESjwk: JWK = OctetSequenceKey(
        Base64URL("GawgguFyGrWKav7AX4VKUg"),
        KeyUse.ENCRYPTION, null, JWEAlgorithm.A128KW,
        AESkid, null, null, null, null, null
    )


    private val keys: Map<String, JWK> = mapOf(RSAkid to RSAjwk)

    private val keys_2: Map<String, JWK> = mapOf(
        RSAkid to RSAjwk,
        RSAkid_2 to RSAjwk_2
    )

    private val keys_3: Map<String, JWK> = mapOf(AESkid to AESjwk)

    private val keys_4: Map<String, JWK> = mapOf(
        RSAkid to RSAjwk,
        RSAkid_2 to RSAjwk_2,
        AESkid to AESjwk,
    )


    private val keys_list: MutableList<JWK> = LinkedList()

    private lateinit var service: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_2: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_3: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_4: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_ks: DefaultJWTEncryptionAndDecryptionService


    @BeforeEach
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class, JOSEException::class)
    fun prepare() {
        service = DefaultJWTEncryptionAndDecryptionService(keys)
        service_2 = DefaultJWTEncryptionAndDecryptionService(keys_2)
        service_3 = DefaultJWTEncryptionAndDecryptionService(keys_3)
        service_4 = DefaultJWTEncryptionAndDecryptionService(keys_4)

        claimsSet = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject)
            .build()

        // Key Store
        keys_list.add(RSAjwk)
        keys_list.add(AESjwk)
        val jwkSet = JWKSet(keys_list)
        val keyStore = JWKSetKeyStore(jwkSet)

        service_ks = DefaultJWTEncryptionAndDecryptionService(keyStore)
    }


    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun decrypt_RSA() {
        assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service.defaultDecryptionKeyId = RSAkid
        service.defaultEncryptionKeyId = RSAkid

        val jwt = JWEObject.parse(compactSerializedJwe)

        assertNull(jwt.payload) // observe..nothing is there

        service.decryptJwt(jwt)
        val result = jwt.payload.toString() // and voila! decrypto-magic

        assertEquals(plainText, result)
    }


    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun encryptThenDecrypt_RSA() {
        assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service.defaultDecryptionKeyId = RSAkid
        service.defaultEncryptionKeyId = RSAkid

        assertEquals(RSAkid, service.defaultEncryptionKeyId)
        assertEquals(RSAkid, service.defaultDecryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)

        service.encryptJwt(jwt)
        val serialized = jwt.serialize()

        val encryptedJwt = EncryptedJWT.parse(serialized)
        assertNull(encryptedJwt.jwtClaimsSet)
        service.decryptJwt(encryptedJwt)

        val resultClaims = encryptedJwt.jwtClaimsSet

        assertEquals(claimsSet.issuer, resultClaims.issuer)
        assertEquals(claimsSet.subject, resultClaims.subject)
    }


    // The same as encryptThenDecrypt_RSA() but relies on the key from the map
    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun encryptThenDecrypt_nullID() {
        assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service.defaultDecryptionKeyId = null
        service.defaultEncryptionKeyId = null

        assertEquals(RSAkid, service.defaultEncryptionKeyId)
        assertEquals(RSAkid, service.defaultDecryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)

        service.encryptJwt(jwt)
        val serialized = jwt.serialize()

        val encryptedJwt = EncryptedJWT.parse(serialized)
        assertNull(encryptedJwt.jwtClaimsSet)
        service.decryptJwt(encryptedJwt)

        val resultClaims = encryptedJwt.jwtClaimsSet

        assertEquals(claimsSet.issuer, resultClaims.issuer)
        assertEquals(claimsSet.subject, resultClaims.subject)
    }


    @Test
    @Throws(NoSuchAlgorithmException::class)
    fun encrypt_nullID_oneKey() {
        assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        assertThrows<IllegalStateException> {
            service_2.defaultEncryptionKeyId = null
            assertEquals(null, service_2.defaultEncryptionKeyId)

            val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

            val jwt = EncryptedJWT(header, claimsSet)

            service_2.encryptJwt(jwt)
            assertEquals(null, service_2.defaultEncryptionKeyId)
        }
    }


    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun decrypt_nullID() {
        assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        assertThrows<IllegalStateException> {
            service_2.defaultEncryptionKeyId = RSAkid
            service_2.defaultDecryptionKeyId = null

            assertEquals(RSAkid, service_2.defaultEncryptionKeyId)
            assertEquals(null, service_2.defaultDecryptionKeyId)

            val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

            val jwt = EncryptedJWT(header, claimsSet)
            service_2.encryptJwt(jwt)
            val serialized = jwt.serialize()

            val encryptedJwt = EncryptedJWT.parse(serialized)
            assertNull(encryptedJwt.jwtClaimsSet)

            assertEquals(null, service_2.defaultDecryptionKeyId)
            service_2.decryptJwt(encryptedJwt)
        }

    }


    @Test
    @Throws(ParseException::class)
    fun setThenGetDefAlg() {
        service.defaultAlgorithm = JWEAlgorithm.A128KW
        assertEquals(JWEAlgorithm.A128KW, service.defaultAlgorithm)

        service.defaultAlgorithm = JWEAlgorithm.RSA_OAEP
        assertEquals(JWEAlgorithm.RSA_OAEP, service.defaultAlgorithm)
    }


    @Throws(ParseException::class)
    @Test
    fun getAllPubkeys() {
        val keys2check = service_2.allPublicKeys
        assertEquals(
            JSONObjectUtils.getString(RSAjwk.toPublicJWK().toJSONObject(), "e"),
            JSONObjectUtils.getString(keys2check[RSAkid]!!.toJSONObject(), "e")
        )
        assertEquals(
            JSONObjectUtils.getString(RSAjwk_2.toPublicJWK().toJSONObject(), "e"),
            JSONObjectUtils.getString(keys2check[RSAkid_2]!!.toJSONObject(), "e")
        )

        assertTrue(service_3.allPublicKeys.isEmpty())
    }


    @Throws(ParseException::class)
    @Test
    fun getAllCryptoAlgsSupported() {
        assertTrue(JWEAlgorithm.RSA_OAEP in service_4.allEncryptionAlgsSupported)
        assertTrue(JWEAlgorithm.RSA1_5 in service_4.allEncryptionAlgsSupported)
        assertTrue(JWEAlgorithm.DIR in service_4.allEncryptionAlgsSupported)
        assertTrue(EncryptionMethod.A128CBC_HS256 in service_4.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A128GCM in service_4.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A192CBC_HS384 in service_4.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A192GCM in service_4.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A256GCM in service_4.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A256CBC_HS512 in service_4.allEncryptionEncsSupported)

        assertTrue(JWEAlgorithm.RSA_OAEP in service_ks.allEncryptionAlgsSupported)
        assertTrue(JWEAlgorithm.RSA1_5 in service_ks.allEncryptionAlgsSupported)
        assertTrue(JWEAlgorithm.DIR in service_ks.allEncryptionAlgsSupported)
        assertTrue(EncryptionMethod.A128CBC_HS256 in service_ks.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A128GCM in service_ks.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A192CBC_HS384 in service_ks.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A192GCM in service_ks.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A256GCM in service_ks.allEncryptionEncsSupported)
        assertTrue(EncryptionMethod.A256CBC_HS512 in service_ks.allEncryptionEncsSupported)
    }


    @Throws(ParseException::class)
    @Test
    fun getDefaultCryptoKeyId() {
        // Test set/getDefaultEn/DecryptionKeyId

        assertNull(service_4.defaultEncryptionKeyId)
        assertEquals(null, service_4.defaultDecryptionKeyId)
        service_4.defaultEncryptionKeyId = RSAkid
        service_4.defaultDecryptionKeyId = AESkid
        assertEquals(RSAkid, service_4.defaultEncryptionKeyId)
        assertEquals(AESkid, service_4.defaultDecryptionKeyId)

        assertEquals(null, service_ks.defaultEncryptionKeyId)
        assertEquals(null, service_ks.defaultDecryptionKeyId)
        service_ks.defaultEncryptionKeyId = RSAkid
        service_ks.defaultDecryptionKeyId = AESkid
        assertEquals(RSAkid, service_ks.defaultEncryptionKeyId)
        assertEquals(AESkid, service_ks.defaultDecryptionKeyId)
    }

    companion object {
        private val logger = getLogger<TestDefaultJWTEncryptionAndDecryptionService>()
    }
}
