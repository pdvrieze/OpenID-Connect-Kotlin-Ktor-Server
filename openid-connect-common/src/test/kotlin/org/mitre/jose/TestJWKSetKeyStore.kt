/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.jose

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mitre.jose.keystore.JWKSetKeyStore
import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import java.io.File
import java.io.FileOutputStream
import java.util.*

/**
 * @author tsitkov
 */
class TestJWKSetKeyStore {
    private val RSAkid = "rsa_1"
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

    private val RSAkid_rsa2 = "rsa_2"
    private val RSAjwk_rsa2: JWK = RSAKey(
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
        KeyUse.ENCRYPTION, null, JWEAlgorithm.RSA1_5, RSAkid_rsa2, null, null, null, null, null
    )


    var keys_list: MutableList<JWK> = LinkedList()
    private lateinit var jwkSet: JWKSet
    private val ks_file = "ks.txt"
    private val ks_file_badJWK = "ks_badJWK.txt"

    @BeforeEach
    fun prepare() {
        keys_list.add(RSAjwk)
        keys_list.add(RSAjwk_rsa2)
        jwkSet = JWKSet(keys_list)
        jwkSet.keys

        val jwtbyte = jwkSet.toString().toByteArray()
        val out = FileOutputStream(ks_file)
        out.write(jwtbyte)
        out.close()
    }

    @AfterEach
    fun cleanup() {
        val f1 = File(ks_file)
        if (f1.exists()) {
            f1.delete()
        }
        val f2 = File(ks_file_badJWK)
        if (f2.exists()) {
            f2.delete()
        }
    }

    /* Constructors with no valid Resource setup */
    @Test
    fun ksConstructorTest() {
        val ks = JWKSetKeyStore(jwkSet)
        assertEquals(ks.jwkSet, jwkSet)

//        val ks_empty = JWKSetKeyStore("")
//        assertEquals(ks_empty.jwkSet, null)
    }

    /* Misformatted JWK */
    @Test
    fun ksBadJWKinput() {
        assertThrows<IllegalArgumentException> {
            val jwtbyte = RSAjwk.toString().toByteArray()
            val out = FileOutputStream(ks_file_badJWK)
            out.write(jwtbyte)
            out.close()

            val loc: Resource = FileSystemResource(ks_file_badJWK)
            assertTrue(loc.exists())
            val ks_badJWK = JWKSetKeyStore(loc)

            assertEquals(loc.filename, ks_file_badJWK)
            assertEquals(loc, ks_badJWK.location)
        }
    }

    /* Empty constructor with valid Resource */
    @Test
    fun ksEmptyConstructorkLoc() {
        val file = File(ks_file)

        val loc: Resource = FileSystemResource(file)
        assertTrue(loc.exists())
        assertTrue(loc.isReadable)

        val ks = JWKSetKeyStore(loc)

        assertEquals(loc.filename, ks.location!!.filename)
    }

}
