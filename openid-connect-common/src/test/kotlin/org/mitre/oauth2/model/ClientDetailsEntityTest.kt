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
package org.mitre.oauth2.model

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.*

/**
 * @author jricher
 */
class ClientDetailsEntityTest {
    /**
     * Test method for [org.mitre.oauth2.model.ClientDetailsEntity].
     */
    @Test
    fun testClientDetailsEntity() {
        val now = Date()

        val c = ClientDetailsEntity.Builder(
            clientId = "s6BhdRkqt3",
            clientSecret = "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            applicationType = OAuthClientDetails.AppType.WEB,
            redirectUris = setOf("https://client.example.org/callback", "https://client.example.org/callback2"),
            clientName = "My Example",
            logoUri = "https://client.example.org/logo.png",
            subjectType = OAuthClientDetails.SubjectType.PAIRWISE,
            sectorIdentifierUri = "https://other.example.net/file_of_redirect_uris.json",
            tokenEndpointAuthMethod = OAuthClientDetails.AuthMethod.SECRET_BASIC,
            jwksUri = "https://client.example.org/my_public_keys.jwks",
            userInfoEncryptedResponseAlg = JWEAlgorithm.RSA1_5,
            userInfoEncryptedResponseEnc = EncryptionMethod.A128CBC_HS256,
            contacts = setOf("ve7jtb@example.org", "mary@example.org"),
            requestUris = setOf("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"),
            createdAt = now,
            accessTokenValiditySeconds = 600
        ).build()


        assertEquals("s6BhdRkqt3", c.clientId)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", c.clientSecret)
        assertEquals(OAuthClientDetails.AppType.WEB, c.applicationType)
        assertEquals(setOf("https://client.example.org/callback", "https://client.example.org/callback2"), c.redirectUris)
        assertEquals("My Example", c.clientName)
        assertEquals("https://client.example.org/logo.png", c.logoUri)
        assertEquals(OAuthClientDetails.SubjectType.PAIRWISE, c.subjectType)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", c.sectorIdentifierUri)
        assertEquals(OAuthClientDetails.AuthMethod.SECRET_BASIC, c.tokenEndpointAuthMethod)
        assertEquals("https://client.example.org/my_public_keys.jwks", c.jwksUri)
        assertEquals(JWEAlgorithm.RSA1_5, c.userInfoEncryptedResponseAlg)
        assertEquals(EncryptionMethod.A128CBC_HS256, c.userInfoEncryptedResponseEnc)
        assertEquals(setOf("ve7jtb@example.org", "mary@example.org"), c.contacts)
        assertEquals(setOf("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"), c.requestUris)
        assertEquals(now, c.createdAt)
        assertEquals(600, c.accessTokenValiditySeconds?.toLong())
    }
}
