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
/**
 *
 */
package org.mitre.openid.connect

import com.google.common.collect.ImmutableSet
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parseRegistered
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.serialize
import java.util.*

/**
 * @author jricher
 */
class ClientDetailsEntityJsonProcessorTest {
    /**
     * Test method for [org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse].
     */
    @Test
    fun testParse() {
        val json = """  {
   "application_type": "web",
   "redirect_uris":
     ["https://client.example.org/callback",
      "https://client.example.org/callback2"],
   "client_name": "My Example",
   "client_name#ja-Jpan-JP":
     "クライアント名",
   "response_types": ["code", "token"],
   "grant_types": ["authorization_code", "implicit"],
   "logo_uri": "https://client.example.org/logo.png",
   "subject_type": "pairwise",
   "sector_identifier_uri":
     "https://other.example.net/file_of_redirect_uris.json",
   "token_endpoint_auth_method": "client_secret_basic",
   "jwks_uri": "https://client.example.org/my_public_keys.jwks",
   "userinfo_encrypted_response_alg": "RSA1_5",
   "userinfo_encrypted_response_enc": "A128CBC-HS256",
   "contacts": ["ve7jtb@example.org", "mary@example.org"],
   "request_uris":
     ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
  }"""
        val c = parse(json)

        assertEquals(ClientDetailsEntity.AppType.WEB, c!!.applicationType)
        assertEquals(ImmutableSet.of("https://client.example.org/callback", "https://client.example.org/callback2"), c.redirectUris)
        assertEquals("My Example", c.clientName)
        assertEquals(ImmutableSet.of("code", "token"), c.responseTypes)
        assertEquals(ImmutableSet.of("authorization_code", "implicit"), c.grantTypes)
        assertEquals("https://client.example.org/logo.png", c.logoUri)
        assertEquals(ClientDetailsEntity.SubjectType.PAIRWISE, c.subjectType)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", c.sectorIdentifierUri)
        assertEquals(ClientDetailsEntity.AuthMethod.SECRET_BASIC, c.tokenEndpointAuthMethod)
        assertEquals("https://client.example.org/my_public_keys.jwks", c.jwksUri)
        assertEquals(JWEAlgorithm.RSA1_5, c.userInfoEncryptedResponseAlg)
        assertEquals(EncryptionMethod.A128CBC_HS256, c.userInfoEncryptedResponseEnc)
        assertEquals(ImmutableSet.of("ve7jtb@example.org", "mary@example.org"), c.contacts)
        assertEquals(ImmutableSet.of("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"), c.requestUris)
    }

    /**
     * Test method for [org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parseRegistered].
     */
    @Test
    fun testParseRegistered() {
        val json = """  {
   "client_id": "s6BhdRkqt3",
   "client_secret":
     "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
   "client_secret_expires_at": 1577858400,
   "registration_access_token":
     "this.is.an.access.token.value.ffx83",
   "registration_client_uri":
     "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
   "token_endpoint_auth_method":
     "client_secret_basic",
   "application_type": "web",
   "redirect_uris":
     ["https://client.example.org/callback",
      "https://client.example.org/callback2"],
   "client_name": "My Example",
   "client_name#ja-Jpan-JP":
     "クライアント名",
   "response_types": ["code", "token"],
   "grant_types": ["authorization_code", "implicit"],
   "logo_uri": "https://client.example.org/logo.png",
   "subject_type": "pairwise",
   "sector_identifier_uri":
     "https://other.example.net/file_of_redirect_uris.json",
   "jwks_uri": "https://client.example.org/my_public_keys.jwks",
   "userinfo_encrypted_response_alg": "RSA1_5",
   "userinfo_encrypted_response_enc": "A128CBC-HS256",
   "contacts": ["ve7jtb@example.org", "mary@example.org"],
   "request_uris":
     ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
  }"""

        val c = parseRegistered(json)


        assertEquals("s6BhdRkqt3", c!!.clientId)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", c.clientSecret)
        assertEquals(Date(1577858400L * 1000L), c.clientSecretExpiresAt)
        assertEquals("this.is.an.access.token.value.ffx83", c.registrationAccessToken)
        assertEquals("https://server.example.com/connect/register?client_id=s6BhdRkqt3", c.registrationClientUri)
        assertEquals(ClientDetailsEntity.AppType.WEB, c.applicationType)
        assertEquals(ImmutableSet.of("https://client.example.org/callback", "https://client.example.org/callback2"), c.redirectUris)
        assertEquals("My Example", c.clientName)
        assertEquals(ImmutableSet.of("code", "token"), c.responseTypes)
        assertEquals(ImmutableSet.of("authorization_code", "implicit"), c.grantTypes)
        assertEquals("https://client.example.org/logo.png", c.logoUri)
        assertEquals(ClientDetailsEntity.SubjectType.PAIRWISE, c.subjectType)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", c.sectorIdentifierUri)
        assertEquals(ClientDetailsEntity.AuthMethod.SECRET_BASIC, c.tokenEndpointAuthMethod)
        assertEquals("https://client.example.org/my_public_keys.jwks", c.jwksUri)
        assertEquals(JWEAlgorithm.RSA1_5, c.userInfoEncryptedResponseAlg)
        assertEquals(EncryptionMethod.A128CBC_HS256, c.userInfoEncryptedResponseEnc)
        assertEquals(ImmutableSet.of("ve7jtb@example.org", "mary@example.org"), c.contacts)
        assertEquals(ImmutableSet.of("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"), c.requestUris)
    }

    /**
     * Test method for [org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.serialize].
     */
    @Test
    fun testSerialize() {
        val c = RegisteredClient()

        c.clientId = "s6BhdRkqt3"
        c.clientSecret = "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk"
        c.clientSecretExpiresAt = Date(1577858400L * 1000L)
        c.registrationAccessToken = "this.is.an.access.token.value.ffx83"
        c.registrationClientUri = "https://server.example.com/connect/register?client_id=s6BhdRkqt3"
        c.applicationType = ClientDetailsEntity.AppType.WEB
        c.redirectUris = ImmutableSet.of("https://client.example.org/callback", "https://client.example.org/callback2")
        c.clientName = "My Example"
        c.responseTypes = ImmutableSet.of("code", "token")
        c.grantTypes = ImmutableSet.of("authorization_code", "implicit")
        c.logoUri = "https://client.example.org/logo.png"
        c.subjectType = ClientDetailsEntity.SubjectType.PAIRWISE
        c.sectorIdentifierUri = "https://other.example.net/file_of_redirect_uris.json"
        c.tokenEndpointAuthMethod = ClientDetailsEntity.AuthMethod.SECRET_BASIC
        c.jwksUri = "https://client.example.org/my_public_keys.jwks"
        c.userInfoEncryptedResponseAlg = JWEAlgorithm.RSA1_5
        c.userInfoEncryptedResponseEnc = EncryptionMethod.A128CBC_HS256
        c.contacts = ImmutableSet.of("ve7jtb@example.org", "mary@example.org")
        c.requestUris = ImmutableSet.of("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")

        val j = serialize(c)

        assertEquals("s6BhdRkqt3", j!!["client_id"].asString)
        assertEquals("ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk", j["client_secret"].asString)
        assertEquals(1577858400L, j["client_secret_expires_at"].asNumber)
        assertEquals("this.is.an.access.token.value.ffx83", j["registration_access_token"].asString)
        assertEquals("https://server.example.com/connect/register?client_id=s6BhdRkqt3", j["registration_client_uri"].asString)
        assertEquals(ClientDetailsEntity.AppType.WEB.value, j["application_type"].asString)
        for (e in j["redirect_uris"].asJsonArray) {
            assertTrue(
                ImmutableSet.of("https://client.example.org/callback", "https://client.example.org/callback2")
                    .contains(e.asString)
            )
        }
        assertEquals("My Example", j["client_name"].asString)
        for (e in j["response_types"].asJsonArray) {
            assertTrue(ImmutableSet.of("code", "token").contains(e.asString))
        }
        for (e in j["grant_types"].asJsonArray) {
            assertTrue(ImmutableSet.of("authorization_code", "implicit").contains(e.asString))
        }
        assertEquals("https://client.example.org/logo.png", j["logo_uri"].asString)
        assertEquals(ClientDetailsEntity.SubjectType.PAIRWISE.value, j["subject_type"].asString)
        assertEquals("https://other.example.net/file_of_redirect_uris.json", j["sector_identifier_uri"].asString)
        assertEquals(ClientDetailsEntity.AuthMethod.SECRET_BASIC.value, j["token_endpoint_auth_method"].asString)
        assertEquals("https://client.example.org/my_public_keys.jwks", j["jwks_uri"].asString)
        assertEquals(JWEAlgorithm.RSA1_5.name, j["userinfo_encrypted_response_alg"].asString)
        assertEquals(EncryptionMethod.A128CBC_HS256.name, j["userinfo_encrypted_response_enc"].asString)
        for (e in j["contacts"].asJsonArray) {
            assertTrue(ImmutableSet.of("ve7jtb@example.org", "mary@example.org").contains(e.asString))
        }
        for (e in j["request_uris"].asJsonArray) {
            assertTrue(
                ImmutableSet.of("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")
                    .contains(e.asString)
            )
        }
    }
}
