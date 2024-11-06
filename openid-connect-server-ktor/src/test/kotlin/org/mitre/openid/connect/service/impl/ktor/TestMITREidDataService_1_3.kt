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
package org.mitre.openid.connect.service.impl.ktor

import com.nimbusds.jwt.JWTParser
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.fail
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.KtorAuthenticationHolder
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.request.AuthorizationRequest.Approval
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.openid.connect.ktor.assertIs
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.service.KtorIdDataService
import org.mitre.openid.connect.service.KtorIdDataService.Companion.ACCESSTOKENS
import org.mitre.openid.connect.service.KtorIdDataService.Companion.AUTHENTICATIONHOLDERS
import org.mitre.openid.connect.service.KtorIdDataService.Companion.BLACKLISTEDSITES
import org.mitre.openid.connect.service.KtorIdDataService.Companion.CLIENTS
import org.mitre.openid.connect.service.KtorIdDataService.Companion.GRANTS
import org.mitre.openid.connect.service.KtorIdDataService.Companion.REFRESHTOKENS
import org.mitre.openid.connect.service.KtorIdDataService.Companion.SYSTEMSCOPES
import org.mitre.openid.connect.service.KtorIdDataService.Companion.WHITELISTEDSITES
import org.mitre.util.asBoolean
import org.mitre.util.asString
import org.mitre.util.getLogger
import org.mockito.ArgumentCaptor
import org.mockito.Captor
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import java.io.IOException
import java.text.ParseException
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestMITREidDataService_1_3 : TestMITREiDDataServiceBase<KtorIdDataService_1_3>() {

    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    override lateinit var dataService: KtorIdDataService_1_3

    @BeforeEach
    fun prepare() {
        dataService = KtorIdDataService_1_3(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(KtorIdDataService_1_3::class)
    }

    @Test
    override fun testImportRefreshTokens() {
        super.testImportRefreshTokens()
    }

    @Test
    override fun testImportAccessTokens() {
        super.testImportAccessTokens()
    }

    @Test
    override fun testImportClients() {
        super.testImportClients()
    }

    @Test
    override fun testImportBlacklistedSites() {
        super.testImportBlacklistedSites()
    }

    @Test
    override fun testImportWhitelistedSites() {
        super.testImportWhitelistedSites()
    }

    @Test
    override fun testImportGrants() {
        super.testImportGrants()
    }

    @Test
    fun testImportAuthenticationHolders() {
        testImportAuthenticationHolders(false)
    }

    @Test
    fun testImportSystemScopes() {
        testImportSystemScopes(true)
    }

    @Test
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        testFixRefreshTokenAuthHolderReferencesOnImport(1)
    }

    @Test
    fun testExportRefreshTokens() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<KtorAuthenticationHolder>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2RefreshTokenEntity(
            id = 1L,
            client = mockedClient1,
            expirationInstant = expirationDate1,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ."),
            authenticationHolder = mockedAuthHolder1,
        )

        val expirationDate2 = instant("2015-01-07T18:31:50.079+00:00")

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<KtorAuthenticationHolder>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val token2 = OAuth2RefreshTokenEntity(
            id = 2L,
            client = mockedClient2,
            expirationInstant = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ."),
            authenticationHolder = mockedAuthHolder2,
        )

        val allRefreshTokens: Set<OAuth2RefreshTokenEntity> = setOf(token1, token2)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(allRefreshTokens)
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val elem = Json.parseToJsonElement(data)
        val root = elem.jsonObject

        // make sure the root is there
        assertTrue(KtorIdDataService.MITREID_CONNECT_1_3 in root)

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(CLIENTS in config)
        assertTrue(GRANTS in config)
        assertTrue(WHITELISTEDSITES in config)
        assertTrue(BLACKLISTEDSITES in config)
        assertTrue(REFRESHTOKENS in config)
        assertTrue(ACCESSTOKENS in config)
        assertTrue(SYSTEMSCOPES in config)
        assertTrue(AUTHENTICATIONHOLDERS in config)

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])


        // check our refresh token list (this test)
        val refreshTokens = config[REFRESHTOKENS]!!.jsonArray

        assertEquals(2, refreshTokens.size)
        // check for both of our refresh tokens in turn
        val checked: MutableSet<OAuth2RefreshTokenEntity> = HashSet()
        for (e in refreshTokens) {
            assertIs<JsonObject>(e)
            val token = e.jsonObject

            val compare: OAuth2RefreshTokenEntity? = when (token["id"]!!.jsonPrimitive.long) {
                token1.id -> token1
                token2.id -> token2
                else -> null
            }

            if (compare == null) {
                fail("Could not find matching id: ${token["id"]}")
            } else {
                assertEquals(compare.id, token["id"]?.jsonPrimitive?.long)
                assertEquals(compare.client!!.clientId, token["clientId"].asString())
                assertEquals(formatter.format(compare.expirationInstant), token["expiration"].asString())
                assertEquals(compare.value, token["value"].asString())
                assertEquals(compare.authenticationHolder.id, token["authenticationHolderId"]!!.jsonPrimitive.long)
                checked.add(compare)
            }
        }
        // make sure all of our refresh tokens were found
        assertTrue(checked.containsAll(allRefreshTokens))
    }

    @Test
    fun testExportAccessTokens() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<KtorAuthenticationHolder>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2AccessTokenEntity(
            id = 1L,
            client = mockedClient1,
            expirationInstant = expirationDate1,
            jwt = JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0"),
            authenticationHolder = mockedAuthHolder1,
            scope = setOf("id-token"),
            tokenType = "Bearer",
        )

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = instant(expiration2)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<KtorAuthenticationHolder>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val mockRefreshToken2 = mock<OAuth2RefreshTokenEntity>()
        whenever(mockRefreshToken2.id).thenReturn(1L)

        val token2 = OAuth2AccessTokenEntity(
            id = 2L,
            client = mockedClient2,
            expirationInstant = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ"),
            authenticationHolder = mockedAuthHolder2,
            refreshToken = mockRefreshToken2,
            scope = setOf("openid", "offline_access", "email", "profile"),
            tokenType = "Bearer",
        )

        val allAccessTokens: Set<OAuth2AccessTokenEntity> = setOf(token1, token2)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(tokenRepository.allAccessTokens).thenReturn(allAccessTokens)
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val elem = Json.parseToJsonElement(data) as JsonObject
        val root = elem

        // make sure the root is there
        assertTrue(root.contains(KtorIdDataService.MITREID_CONNECT_1_3))

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(config.contains(CLIENTS))
        assertTrue(config.contains(GRANTS))
        assertTrue(config.contains(WHITELISTEDSITES))
        assertTrue(config.contains(BLACKLISTEDSITES))
        assertTrue(config.contains(REFRESHTOKENS))
        assertTrue(config.contains(ACCESSTOKENS))
        assertTrue(config.contains(SYSTEMSCOPES))
        assertTrue(config.contains(AUTHENTICATIONHOLDERS))

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])


        // check our access token list (this test)
        val accessTokens = config[ACCESSTOKENS]!!.jsonArray

        assertEquals(2, accessTokens.size)
        // check for both of our access tokens in turn
        val checked: MutableSet<OAuth2AccessTokenEntity> = HashSet()
        for (e in accessTokens) {
            assertIs<JsonObject>(e)
            val token = e as JsonObject

            val tokenId = token["id"]!!.jsonPrimitive.long

            val compare = when (tokenId) {
                token1.id -> token1
                token2.id -> token2
                else -> fail("Could not find matching id: $tokenId")
            }

            assertEquals(compare.id, tokenId)
            assertEquals(compare.client!!.clientId, token["clientId"].asString())
            assertEquals(formatter.format(compare.expirationInstant), token["expiration"].asString())
            assertEquals(compare.value, token["value"].asString())
            assertEquals(compare.tokenType, token["type"].asString())
            assertEquals(compare.authenticationHolder.id, token["authenticationHolderId"]!!.jsonPrimitive.long)
            assertIs<JsonArray>(token["scope"])
            assertEquals(compare.scope, jsonArrayToStringSet(token["scope"]!!.jsonArray))
            if (token["refreshTokenId"] is JsonNull) {
                assertNull(compare.refreshToken)
            } else {
                assertEquals(compare.refreshToken!!.id, token["refreshTokenId"]!!.jsonPrimitive.long)
            }
            checked.add(compare)
        }
        // make sure all of our access tokens were found
        assertTrue(checked.containsAll(allAccessTokens))
    }

    @Test
    @Throws(IOException::class)
    fun testExportClients() {
        val client1 = ClientDetailsEntity.Builder(
            id = 1L,
            accessTokenValiditySeconds = 3600,
            clientId = "client1",
            clientSecret = "clientsecret1",
            redirectUris = setOf("http://foo.com/"),
            scope = hashSetOf("foo", "bar", "baz", "dolphin"),
            authorizedGrantTypes = hashSetOf("implicit", "authorization_code", "urn:ietf:params:oauth:grant_type:redelegate", "refresh_token"),
            isAllowIntrospection = true,
        ).build()

        val client2 = ClientDetailsEntity.Builder(
            id = 2L,
            accessTokenValiditySeconds = 3600,
            clientId = "client2",
            clientSecret = "clientsecret2",
            redirectUris = setOf("http://bar.baz.com/"),
            scope = hashSetOf("foo", "dolphin", "electric-wombat"),
            authorizedGrantTypes = hashSetOf("client_credentials", "urn:ietf:params:oauth:grant_type:redelegate"),
            isAllowIntrospection = false,
            codeChallengeMethod = PKCEAlgorithm.S256,
        ).build()

        val allClients: Set<ClientDetailsEntity> = setOf(client1, client2)

        whenever(clientRepository.allClients).thenReturn(allClients)
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val root = Json.parseToJsonElement(data).jsonObject

        // make sure the root is there
        assertTrue(KtorIdDataService.MITREID_CONNECT_1_3 in root)

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(CLIENTS in config)
        assertTrue(GRANTS in config)
        assertTrue(WHITELISTEDSITES in config)
        assertTrue(BLACKLISTEDSITES in config)
        assertTrue(REFRESHTOKENS in config)
        assertTrue(ACCESSTOKENS in config)
        assertTrue(SYSTEMSCOPES in config)
        assertTrue(AUTHENTICATIONHOLDERS in config)

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])


        // check our client list (this test)
        val clients = config[CLIENTS]!!.jsonArray

        assertEquals(2, clients.size)
        // check for both of our clients in turn
        val checked: MutableSet<ClientDetailsEntity> = HashSet()
        for (e in clients) {
            assertIs<JsonObject>(e)
            val client = e as JsonObject

            var compare: ClientDetailsEntity? = null
            if (client["clientId"].asString() == client1.clientId) {
                compare = client1
            } else if (client["clientId"].asString() == client2.clientId) {
                compare = client2
            }

            if (compare == null) {
                fail("Could not find matching clientId: ${client["clientId"].asString()}")
            } else {
                assertEquals(compare.clientId, client["clientId"].asString())
                assertEquals(compare.clientSecret, client["secret"].asString())
                assertEquals(compare.accessTokenValiditySeconds, client["accessTokenValiditySeconds"]!!.jsonPrimitive.long.toInt())
                assertEquals(compare.isAllowIntrospection, client["allowIntrospection"].asBoolean())
                assertEquals(compare.redirectUris, jsonArrayToStringSet(client["redirectUris"]!!.jsonArray))
                assertEquals(compare.scope, jsonArrayToStringSet(client["scope"]!!.jsonArray))
                assertEquals(compare.authorizedGrantTypes, jsonArrayToStringSet(client["grantTypes"]!!.jsonArray))
                assertEquals(compare.codeChallengeMethod, if ((client.contains("codeChallengeMethod") && client["codeChallengeMethod"] !is JsonNull)) parse(client["codeChallengeMethod"].asString()) else null)
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allClients))
    }

    @Test
    @Throws(IOException::class)
    fun testExportBlacklistedSites() {
        val site1 = BlacklistedSite(
            id = 1L,
            uri = "http://foo.com",
        )

        val site2 = BlacklistedSite(
            id = 2L,
            uri = "http://bar.com",
        )

        val site3 = BlacklistedSite(
            id = 3L,
            uri = "http://baz.com",
        )

        val allBlacklistedSites: Set<BlacklistedSite> = setOf(site1, site2, site3)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(allBlacklistedSites)
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val root = Json.parseToJsonElement(data).jsonObject

        // make sure the root is there
        assertTrue(KtorIdDataService.MITREID_CONNECT_1_3 in root)

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(CLIENTS in config)
        assertTrue(GRANTS in config)
        assertTrue(WHITELISTEDSITES in config)
        assertTrue(BLACKLISTEDSITES in config)
        assertTrue(REFRESHTOKENS in config)
        assertTrue(ACCESSTOKENS in config)
        assertTrue(SYSTEMSCOPES in config)
        assertTrue(AUTHENTICATIONHOLDERS in config)

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])

        // check our scope list (this test)
        val sites = config[BLACKLISTEDSITES]!!.jsonArray

        assertEquals(3, sites.size)
        // check for both of our sites in turn
        val checked: MutableSet<BlacklistedSite> = HashSet()
        for (e in sites) {
            assertIs<JsonObject>(e)
            val site = e.jsonObject

            var compare: BlacklistedSite? = null
            if (site["id"]!!.jsonPrimitive.long == site1.id) {
                compare = site1
            } else if (site["id"]!!.jsonPrimitive.long == site2.id) {
                compare = site2
            } else if (site["id"]!!.jsonPrimitive.long == site3.id) {
                compare = site3
            }

            if (compare == null) {
                fail("Could not find matching blacklisted site id: ${site["id"].asString()}")
            } else {
                assertEquals(compare.uri, site["uri"].asString())
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allBlacklistedSites))
    }

    @Test
    @Throws(IOException::class)
    fun testExportWhitelistedSites() {
        val site1 = WhitelistedSite()
        site1.id = 1L
        site1.clientId = "foo"

        val site2 = WhitelistedSite()
        site2.id = 2L
        site2.clientId = "bar"

        val site3 = WhitelistedSite()
        site3.id = 3L
        site3.clientId = "baz"

        val allWhitelistedSites: Set<WhitelistedSite> = setOf(site1, site2, site3)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(allWhitelistedSites)
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val root = Json.parseToJsonElement(data).jsonObject

        // make sure the root is there
        assertTrue(root.contains(KtorIdDataService.MITREID_CONNECT_1_3))

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(config.contains(CLIENTS))
        assertTrue(config.contains(GRANTS))
        assertTrue(config.contains(WHITELISTEDSITES))
        assertTrue(config.contains(BLACKLISTEDSITES))
        assertTrue(config.contains(REFRESHTOKENS))
        assertTrue(config.contains(ACCESSTOKENS))
        assertTrue(config.contains(SYSTEMSCOPES))
        assertTrue(config.contains(AUTHENTICATIONHOLDERS))

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])

        // check our scope list (this test)
        val sites = config[WHITELISTEDSITES]!!.jsonArray

        assertEquals(3, sites.size)
        // check for both of our sites in turn
        val checked: MutableSet<WhitelistedSite> = HashSet()
        for (e in sites) {
            assertIs<JsonObject>(e)
            val site = e.jsonObject

            var compare: WhitelistedSite? = null
            if (site["id"]!!.jsonPrimitive.long == site1.id) {
                compare = site1
            } else if (site["id"]!!.jsonPrimitive.long == site2.id) {
                compare = site2
            } else if (site["id"]!!.jsonPrimitive.long == site3.id) {
                compare = site3
            }

            if (compare == null) {
                fail("Could not find matching whitelisted site id: " + site["id"].asString())
            } else {
                assertEquals(compare.clientId, site["clientId"].asString())
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allWhitelistedSites))
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testExportGrants() {
        val creationDate1 = instant("2014-09-10T22:49:44.090+00:00")
        val accessDate1 = instant("2014-09-10T23:49:44.090+00:00")

        val mockToken1 = mock<OAuth2AccessTokenEntity>()
        whenever(mockToken1.id).thenReturn(1L)

        val site1 = ApprovedSite(
            id = 1L,
            clientId = "foo",
            creationDate = creationDate1,
            accessDate = accessDate1,
            userId = "user1",
            allowedScopes = setOf("openid", "phone"),
        )
        whenever(mockToken1.approvedSite).thenReturn(site1)

        val creationDate2 = instant("2014-09-11T18:49:44.090+00:00")
        val accessDate2 = instant("2014-09-11T20:49:44.090+00:00")
        val timeoutDate2 = instant("2014-10-01T20:49:44.090+00:00")

        val site2 = ApprovedSite(
            id = 2L,
            clientId = "bar",
            creationDate = creationDate2,
            accessDate = accessDate2,
            userId = "user2",
            allowedScopes = setOf("openid", "offline_access", "email", "profile"),
            timeoutDate = timeoutDate2,
        )

        val allApprovedSites: Set<ApprovedSite> = setOf(site1, site2)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(allApprovedSites)
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val root = Json.parseToJsonElement(data).jsonObject

        // make sure the root is there
        assertTrue(root.contains(KtorIdDataService.MITREID_CONNECT_1_3))

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(config.contains(CLIENTS))
        assertTrue(config.contains(GRANTS))
        assertTrue(config.contains(WHITELISTEDSITES))
        assertTrue(config.contains(BLACKLISTEDSITES))
        assertTrue(config.contains(REFRESHTOKENS))
        assertTrue(config.contains(ACCESSTOKENS))
        assertTrue(config.contains(SYSTEMSCOPES))
        assertTrue(config.contains(AUTHENTICATIONHOLDERS))

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])

        // check our scope list (this test)
        val sites = config[GRANTS]!!.jsonArray

        assertEquals(2, sites.size)
        // check for both of our sites in turn
        val checked: MutableSet<ApprovedSite> = HashSet()
        for (e in sites) {
            assertIs<JsonObject>(e)
            val site = e.jsonObject

            var compare: ApprovedSite? = null
            if (site["id"]!!.jsonPrimitive.long == site1.id) {
                compare = site1
            } else if (site["id"]!!.jsonPrimitive.long == site2.id) {
                compare = site2
            }

            if (compare == null) {
                fail("Could not find matching whitelisted site id: " + site["id"].asString())
            } else {
                assertEquals(compare.clientId, site["clientId"].asString())
                assertEquals(formatter.format(compare.creationDate), site["creationDate"].asString())
                assertEquals(formatter.format(compare.accessDate), site["accessDate"].asString())
                if (site["timeoutDate"] is JsonNull) {
                    assertNull(compare.timeoutDate)
                } else {
                    assertEquals(formatter.format(compare.timeoutDate), site["timeoutDate"].asString())
                }
                assertEquals(compare.userId, site["userId"].asString())
                assertEquals(compare.allowedScopes, jsonArrayToStringSet(site["allowedScopes"]!!.jsonArray))
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allApprovedSites))
    }

    @Test
    @Throws(IOException::class)
    fun testExportAuthenticationHolders() {
        val now = Instant.now()
        val req1 = PlainAuthorizationRequest.Builder(clientId = "client1").also { b ->
            b.approval = Approval(now.minusSeconds(3))
            b.redirectUri = "http://foo.com"
            b.requestTime = now.minusSeconds(2)
        }.build()
        val mockAuth1: SavedUserAuthentication = SavedUserAuthentication(name = "mockAuth1")
//            UsernamePasswordAuthenticationToken("user1", "pass1", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"))
        val auth1 = AuthenticatedAuthorizationRequest(req1, mockAuth1)

        val holder1 = KtorAuthenticationHolder(auth1, id = 1L)

        val req2 = PlainAuthorizationRequest.Builder(clientId = "client2").also { b ->
            b.approval = Approval(now.minusSeconds(1))
            b.redirectUri = "http://bar.com"
            b.requestTime = now
        }.build()
        val auth2 = AuthenticatedAuthorizationRequest(req2, null)

        val holder2 = KtorAuthenticationHolder(auth2, 2L)

        val allAuthHolders: List<KtorAuthenticationHolder> = listOf(holder1, holder2)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(allAuthHolders)
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val elem = Json.parseToJsonElement(data)
        val root = elem.jsonObject

        // make sure the root is there
        assertTrue(root.contains(KtorIdDataService.MITREID_CONNECT_1_3))

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(config.contains(CLIENTS))
        assertTrue(config.contains(GRANTS))
        assertTrue(config.contains(WHITELISTEDSITES))
        assertTrue(config.contains(BLACKLISTEDSITES))
        assertTrue(config.contains(REFRESHTOKENS))
        assertTrue(config.contains(ACCESSTOKENS))
        assertTrue(config.contains(SYSTEMSCOPES))
        assertTrue(config.contains(AUTHENTICATIONHOLDERS))

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])


        // check our holder list (this test)
        val holders = config[AUTHENTICATIONHOLDERS]!!.jsonArray

        assertEquals(2, holders.size)
        // check for both of our clients in turn
        val checked: MutableSet<KtorAuthenticationHolder> = HashSet()
        for (e in holders) {
            assertIs<JsonObject>(e)
            val holder = e.jsonObject

            var compare: KtorAuthenticationHolder? = null
            if (holder["id"]!!.jsonPrimitive.long == holder1.id) {
                compare = holder1
            } else if (holder["id"]!!.jsonPrimitive.long == holder2.id) {
                compare = holder2
            }

            if (compare == null) {
                fail("Could not find matching authentication holder id: " + holder["id"].asString())
            } else {
                assertEquals(compare.clientId, holder["clientId"].asString())
                assertEquals(compare.isApproved, holder["approved"].asBoolean())
                assertEquals(compare.redirectUri, holder["redirectUri"].asString())
                if (compare.userAuth != null) {
                    assertIs<JsonObject>(holder["savedUserAuthentication"])
                    val savedAuth = holder["savedUserAuthentication"]!!.jsonObject
                    assertEquals(compare.userAuth!!.name, savedAuth["name"].asString())
                    val actualAuthenticated = when (val a = savedAuth["authenticated"]) {
                        is JsonNull -> null
                        else -> a.asBoolean()
                    }
                    assertEquals(compare.userAuth!!.isAuthenticated, actualAuthenticated)
                    assertEquals(compare.userAuth!!.sourceClass, savedAuth["sourceClass"]?.asString())
                }
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allAuthHolders))
    }

    @Test
    @Throws(IOException::class)
    fun testExportSystemScopes() {
        val scope1 = SystemScope(
            id = 1L,
            value = "scope1",
            description = "Scope 1",
            isRestricted = true,
            isDefaultScope = false,
            icon = "glass",
        )

        val scope2 = SystemScope(
            id = 2L,
            value = "scope2",
            description = "Scope 2",
            isRestricted = false,
            isDefaultScope = false,
            icon = "ball",
        )

        val scope3 = SystemScope(
            id = 3L,
            value = "scope3",
            description = "Scope 3",
            isRestricted = false,
            isDefaultScope = true,
            icon = "road",
        )

        val allScopes: Set<SystemScope> = setOf(scope1, scope2, scope3)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(ArrayList())
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(allScopes)

        // do the data export
        val data = dataService.exportData()

        // parse the output as a JSON object for testing
        val elem = Json.parseToJsonElement(data)
        val root = elem.jsonObject

        // make sure the root is there
        assertTrue(KtorIdDataService.MITREID_CONNECT_1_3 in root)

        val config = root[KtorIdDataService.MITREID_CONNECT_1_3]!!.jsonObject

        // make sure all the root elements are there
        assertTrue(CLIENTS in config)
        assertTrue(GRANTS in config)
        assertTrue(WHITELISTEDSITES in config)
        assertTrue(BLACKLISTEDSITES in config)
        assertTrue(REFRESHTOKENS in config)
        assertTrue(ACCESSTOKENS in config)
        assertTrue(SYSTEMSCOPES in config)
        assertTrue(AUTHENTICATIONHOLDERS in config)

        // make sure the root elements are all arrays
        assertIs<JsonArray>(config[CLIENTS])
        assertIs<JsonArray>(config[GRANTS])
        assertIs<JsonArray>(config[WHITELISTEDSITES])
        assertIs<JsonArray>(config[BLACKLISTEDSITES])
        assertIs<JsonArray>(config[REFRESHTOKENS])
        assertIs<JsonArray>(config[ACCESSTOKENS])
        assertIs<JsonArray>(config[SYSTEMSCOPES])
        assertIs<JsonArray>(config[AUTHENTICATIONHOLDERS])


        // check our scope list (this test)
        val scopes = config[SYSTEMSCOPES]!!.jsonArray

        assertEquals(3, scopes.size)
        // check for both of our clients in turn
        val checked: MutableSet<SystemScope> = HashSet()
        for (e in scopes) {
            assertIs<JsonObject>(e)
            val scope = e.jsonObject

            var compare: SystemScope? = null
            if (scope["value"].asString() == scope1.value) {
                compare = scope1
            } else if (scope["value"].asString() == scope2.value) {
                compare = scope2
            } else if (scope["value"].asString() == scope3.value) {
                compare = scope3
            }

            if (compare == null) {
                fail("Could not find matching scope value: " + scope["value"].asString())
            } else {
                assertEquals(compare.value, scope["value"].asString())
                assertEquals(compare.description, scope["description"].asString())
                assertEquals(compare.icon, scope["icon"].asString())
                assertEquals(compare.isRestricted, scope["restricted"].asBoolean())
                assertEquals(compare.isDefaultScope, scope["defaultScope"].asBoolean())
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertTrue(checked.containsAll(allScopes))
    }

    private fun jsonArrayToStringSet(a: JsonArray): Set<String> {
        val s: MutableSet<String> = HashSet()
        for (jsonElement in a) {
            s.add(jsonElement.asString())
        }
        return s
    }

    companion object {
        private val logger = getLogger<TestMITREidDataService_1_3>()
    }
}
