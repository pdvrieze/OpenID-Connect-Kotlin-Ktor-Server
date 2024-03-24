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

import com.google.common.collect.ImmutableMap
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
import org.hamcrest.CoreMatchers
import org.junit.Assert
import org.junit.Assume
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.mitre.jose.keystore.JWKSetKeyStore
import org.slf4j.Logger
import org.slf4j.LoggerFactory
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
    private var claimsSet: JWTClaimsSet? = null

    @JvmField
    @Rule
    var exception: ExpectedException = ExpectedException.none()

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


    private val keys: Map<String, JWK> = ImmutableMap.Builder<String, JWK>()
        .put(RSAkid, RSAjwk)
        .build()
    private val keys_2: Map<String, JWK> = ImmutableMap.Builder<String, JWK>()
        .put(RSAkid, RSAjwk)
        .put(RSAkid_2, RSAjwk_2)
        .build()
    private val keys_3: Map<String, JWK> = ImmutableMap.Builder<String, JWK>()
        .put(AESkid, AESjwk)
        .build()
    private val keys_4: Map<String, JWK> = ImmutableMap.Builder<String, JWK>()
        .put(RSAkid, RSAjwk)
        .put(RSAkid_2, RSAjwk_2)
        .put(AESkid, AESjwk)
        .build()


    private val keys_list: MutableList<JWK> = LinkedList()

    private lateinit var service: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_2: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_3: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_4: DefaultJWTEncryptionAndDecryptionService
    private lateinit var service_ks: DefaultJWTEncryptionAndDecryptionService


    @Before
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
        Assume.assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service!!.defaultDecryptionKeyId = RSAkid
        service!!.defaultEncryptionKeyId = RSAkid

        val jwt = JWEObject.parse(compactSerializedJwe)

        Assert.assertThat(jwt.payload, CoreMatchers.nullValue()) // observe..nothing is there

        service!!.decryptJwt(jwt)
        val result = jwt.payload.toString() // and voila! decrypto-magic

        Assert.assertEquals(plainText, result)
    }


    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun encryptThenDecrypt_RSA() {
        Assume.assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service!!.defaultDecryptionKeyId = RSAkid
        service!!.defaultEncryptionKeyId = RSAkid

        Assert.assertEquals(RSAkid, service!!.defaultEncryptionKeyId)
        Assert.assertEquals(RSAkid, service!!.defaultDecryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)

        service!!.encryptJwt(jwt)
        val serialized = jwt.serialize()

        val encryptedJwt = EncryptedJWT.parse(serialized)
        Assert.assertThat(encryptedJwt.jwtClaimsSet, CoreMatchers.nullValue())
        service!!.decryptJwt(encryptedJwt)

        val resultClaims = encryptedJwt.jwtClaimsSet

        Assert.assertEquals(claimsSet!!.issuer, resultClaims.issuer)
        Assert.assertEquals(claimsSet!!.subject, resultClaims.subject)
    }


    // The same as encryptThenDecrypt_RSA() but relies on the key from the map
    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun encryptThenDecrypt_nullID() {
        Assume.assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        service!!.defaultDecryptionKeyId = null
        service!!.defaultEncryptionKeyId = null

        Assert.assertEquals(RSAkid, service!!.defaultEncryptionKeyId)
        Assert.assertEquals(RSAkid, service!!.defaultDecryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)

        service!!.encryptJwt(jwt)
        val serialized = jwt.serialize()

        val encryptedJwt = EncryptedJWT.parse(serialized)
        Assert.assertThat(encryptedJwt.jwtClaimsSet, CoreMatchers.nullValue())
        service!!.decryptJwt(encryptedJwt)

        val resultClaims = encryptedJwt.jwtClaimsSet

        Assert.assertEquals(claimsSet!!.issuer, resultClaims.issuer)
        Assert.assertEquals(claimsSet!!.subject, resultClaims.subject)
    }


    @Test
    @Throws(NoSuchAlgorithmException::class)
    fun encrypt_nullID_oneKey() {
        Assume.assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength

        exception.expect(IllegalStateException::class.java)

        service_2!!.defaultEncryptionKeyId = null
        Assert.assertEquals(null, service_2!!.defaultEncryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)

        service_2!!.encryptJwt(jwt)
        Assert.assertEquals(null, service_2!!.defaultEncryptionKeyId)
    }


    @Test
    @Throws(ParseException::class, NoSuchAlgorithmException::class)
    fun decrypt_nullID() {
        Assume.assumeTrue(
            (JCASupport.isSupported(JWEAlgorithm.RSA_OAEP) // check for algorithm support
                    && JCASupport.isSupported(EncryptionMethod.A256GCM)) && Cipher.getMaxAllowedKeyLength("RC5") >= 256
        ) // check for unlimited crypto strength


        exception.expect(IllegalStateException::class.java)

        service_2!!.defaultEncryptionKeyId = RSAkid
        service_2!!.defaultDecryptionKeyId = null

        Assert.assertEquals(RSAkid, service_2!!.defaultEncryptionKeyId)
        Assert.assertEquals(null, service_2!!.defaultDecryptionKeyId)

        val header = JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A256GCM)

        val jwt = EncryptedJWT(header, claimsSet)
        service_2!!.encryptJwt(jwt)
        val serialized = jwt.serialize()

        val encryptedJwt = EncryptedJWT.parse(serialized)
        Assert.assertThat(encryptedJwt.jwtClaimsSet, CoreMatchers.nullValue())

        Assert.assertEquals(null, service_2!!.defaultDecryptionKeyId)
        service_2!!.decryptJwt(encryptedJwt)
    }


    @Test
    @Throws(ParseException::class)
    fun setThenGetDefAlg() {
        service!!.defaultAlgorithm = JWEAlgorithm.A128KW
        Assert.assertEquals(JWEAlgorithm.A128KW, service!!.defaultAlgorithm)

        service!!.defaultAlgorithm = JWEAlgorithm.RSA_OAEP
        Assert.assertEquals(JWEAlgorithm.RSA_OAEP, service!!.defaultAlgorithm)
    }


    @Throws(ParseException::class)
    @Test
    fun getAllPubkeys() {
        val keys2check = service_2.allPublicKeys
        Assert.assertEquals(
            JSONObjectUtils.getString(RSAjwk.toPublicJWK().toJSONObject(), "e"),
            JSONObjectUtils.getString(keys2check[RSAkid]!!.toJSONObject(), "e")
        )
        Assert.assertEquals(
            JSONObjectUtils.getString(RSAjwk_2.toPublicJWK().toJSONObject(), "e"),
            JSONObjectUtils.getString(keys2check[RSAkid_2]!!.toJSONObject(), "e")
        )

        Assert.assertTrue(service_3.allPublicKeys.isEmpty())
    }


    @Throws(ParseException::class)
    @Test
    fun getAllCryptoAlgsSupported() {
        Assert.assertTrue(service_4.allEncryptionAlgsSupported.contains(JWEAlgorithm.RSA_OAEP))
        Assert.assertTrue(service_4.allEncryptionAlgsSupported.contains(JWEAlgorithm.RSA1_5))
        Assert.assertTrue(service_4.allEncryptionAlgsSupported.contains(JWEAlgorithm.DIR))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A128CBC_HS256))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A128GCM))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A192CBC_HS384))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A192GCM))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A256GCM))
        Assert.assertTrue(service_4.allEncryptionEncsSupported.contains(EncryptionMethod.A256CBC_HS512))

        Assert.assertTrue(service_ks.allEncryptionAlgsSupported.contains(JWEAlgorithm.RSA_OAEP))
        Assert.assertTrue(service_ks.allEncryptionAlgsSupported.contains(JWEAlgorithm.RSA1_5))
        Assert.assertTrue(service_ks.allEncryptionAlgsSupported.contains(JWEAlgorithm.DIR))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A128CBC_HS256))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A128GCM))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A192CBC_HS384))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A192GCM))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A256GCM))
        Assert.assertTrue(service_ks.allEncryptionEncsSupported.contains(EncryptionMethod.A256CBC_HS512))
    }


    @Throws(ParseException::class)
    @Test
    fun getDefaultCryptoKeyId() {
        // Test set/getDefaultEn/DecryptionKeyId

        Assert.assertEquals(null, service_4.defaultEncryptionKeyId)
        Assert.assertEquals(null, service_4.defaultDecryptionKeyId)
        service_4.defaultEncryptionKeyId = RSAkid
        service_4.defaultDecryptionKeyId = AESkid
        Assert.assertEquals(RSAkid, service_4.defaultEncryptionKeyId)
        Assert.assertEquals(AESkid, service_4.defaultDecryptionKeyId)

        Assert.assertEquals(null, service_ks.defaultEncryptionKeyId)
        Assert.assertEquals(null, service_ks.defaultDecryptionKeyId)
        service_ks.defaultEncryptionKeyId = RSAkid
        service_ks.defaultDecryptionKeyId = AESkid
        Assert.assertEquals(RSAkid, service_ks.defaultEncryptionKeyId)
        Assert.assertEquals(AESkid, service_ks.defaultDecryptionKeyId)
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(TestDefaultJWTEncryptionAndDecryptionService::class.java)
    }
}
