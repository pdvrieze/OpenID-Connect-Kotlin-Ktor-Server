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
import org.mitre.oauth2.model.RegisteredClient
import java.sql.Date

/**
 * @author jricher
 */
class RegisteredClientTest {
    /**
     * Test method for [org.mitre.oauth2.model.RegisteredClient.RegisteredClient].
     */
    @Test
    fun testRegisteredClient() {
        // make sure all the pass-through getters and setters work

        val c = RegisteredClient(
            clientSecretExpiresAt = Date(1577858400L * 1000L),
            registrationAccessToken = "this.is.an.access.token.value.ffx83",
            registrationClientUri = "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
            client = ClientDetailsEntity.Builder(
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
            ).build(),
        )


        assertEquals("s6BhdRkqt3", c.clientId)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", c.clientSecret)
        assertEquals(Date(1577858400L * 1000L), c.clientSecretExpiresAt)
        assertEquals("this.is.an.access.token.value.ffx83", c.registrationAccessToken)
        assertEquals("https://server.example.com/connect/register?client_id=s6BhdRkqt3", c.registrationClientUri)
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
    }

    /**
     * Test method for [org.mitre.oauth2.model.RegisteredClient].
     */
    @Test
    fun testRegisteredClientClientDetailsEntity() {
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
        ).build()


        // Create a RegisteredClient based on a ClientDetailsEntity object and set several properties
        val rc = RegisteredClient(
            client = c,
            clientSecretExpiresAt = Date(1577858400L * 1000L),
            registrationAccessToken = "this.is.an.access.token.value.ffx83",
            registrationClientUri = "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
        )

        // make sure all the pass-throughs work
        assertEquals("s6BhdRkqt3", rc.clientId)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", rc.clientSecret)
        assertEquals(Date(1577858400L * 1000L), rc.clientSecretExpiresAt)
        assertEquals("this.is.an.access.token.value.ffx83", rc.registrationAccessToken)
        assertEquals("https://server.example.com/connect/register?client_id=s6BhdRkqt3", rc.registrationClientUri)
        assertEquals(OAuthClientDetails.AppType.WEB, rc.applicationType)
        assertEquals(setOf("https://client.example.org/callback", "https://client.example.org/callback2"), rc.redirectUris)
        assertEquals("My Example", rc.clientName)
        assertEquals("https://client.example.org/logo.png", rc.logoUri)
        assertEquals(OAuthClientDetails.SubjectType.PAIRWISE, rc.subjectType)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", rc.sectorIdentifierUri)
        assertEquals(OAuthClientDetails.AuthMethod.SECRET_BASIC, rc.tokenEndpointAuthMethod)
        assertEquals("https://client.example.org/my_public_keys.jwks", rc.jwksUri)
        assertEquals(JWEAlgorithm.RSA1_5, rc.userInfoEncryptedResponseAlg)
        assertEquals(EncryptionMethod.A128CBC_HS256, rc.userInfoEncryptedResponseEnc)
        assertEquals(setOf("ve7jtb@example.org", "mary@example.org"), rc.contacts)
        assertEquals(setOf("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"), rc.requestUris)
    }

    /**
     * Test method for [org.mitre.oauth2.model.RegisteredClient].
     */
    @Test
    fun testRegisteredClientClientDetailsEntityStringString() {
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
        ).build()

        // Create a RegisteredClient based on a ClientDetails, a token, and a server URI
        val rc =
            RegisteredClient(c, "this.is.an.access.token.value.ffx83", "https://server.example.com/connect/register?client_id=s6BhdRkqt3")

        // make sure all the pass-throughs work
        assertEquals("s6BhdRkqt3", rc.clientId)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", rc.clientSecret)
        assertEquals("this.is.an.access.token.value.ffx83", rc.registrationAccessToken)
        assertEquals("https://server.example.com/connect/register?client_id=s6BhdRkqt3", rc.registrationClientUri)
        assertEquals(OAuthClientDetails.AppType.WEB, rc.applicationType)
        assertEquals(setOf("https://client.example.org/callback", "https://client.example.org/callback2"), rc.redirectUris)
        assertEquals("My Example", rc.clientName)
        assertEquals("https://client.example.org/logo.png", rc.logoUri)
        assertEquals(OAuthClientDetails.SubjectType.PAIRWISE, rc.subjectType)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", rc.sectorIdentifierUri)
        assertEquals(OAuthClientDetails.AuthMethod.SECRET_BASIC, rc.tokenEndpointAuthMethod)
        assertEquals("https://client.example.org/my_public_keys.jwks", rc.jwksUri)
        assertEquals(JWEAlgorithm.RSA1_5, rc.userInfoEncryptedResponseAlg)
        assertEquals(EncryptionMethod.A128CBC_HS256, rc.userInfoEncryptedResponseEnc)
        assertEquals(setOf("ve7jtb@example.org", "mary@example.org"), rc.contacts)
        assertEquals(setOf("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"), rc.requestUris)
    }
}
