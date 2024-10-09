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
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.ktor.assertIs
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.ACCESSTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.AUTHENTICATIONHOLDERS
import org.mitre.openid.connect.service.MITREidDataService.Companion.BLACKLISTEDSITES
import org.mitre.openid.connect.service.MITREidDataService.Companion.CLIENTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.GRANTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.REFRESHTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.SYSTEMSCOPES
import org.mitre.openid.connect.service.MITREidDataService.Companion.WHITELISTEDSITES
import org.mitre.util.asBoolean
import org.mitre.util.asString
import org.mitre.util.getLogger
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.Captor
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.capture
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import org.mockito.stubbing.Answer
import java.io.IOException
import java.text.ParseException
import java.util.*

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestMITREidDataService_1_3 : TestMITREiDDataServiceBase<MITREidDataService_1_3>() {

    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    override lateinit var dataService: MITREidDataService_1_3

    @BeforeEach
    fun prepare() {
        dataService = MITREidDataService_1_3(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(MITREidDataService_1_3::class)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testExportRefreshTokens() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
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

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
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
        assertTrue(MITREidDataService.MITREID_CONNECT_1_3 in root)

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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

            var compare: OAuth2RefreshTokenEntity? = null
            if (token["id"]!!.jsonPrimitive.long == token1.id) {
                compare = token1
            } else if (token["id"]!!.jsonPrimitive.long == token2.id) {
                compare = token2
            }

            if (compare == null) {
                fail("Could not find matching id: ${token["id"].asString()}")
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

    private inner class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }


    @Test
    @Throws(IOException::class, ParseException::class)
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
    @Throws(IOException::class)
    fun testImportSystemScopes() {
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

        val configJson = "{" +
                "\"$CLIENTS\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$REFRESHTOKENS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [], " +
                "\"$SYSTEMSCOPES\": [" +
                "{\"id\":1,\"description\":\"Scope 1\",\"icon\":\"glass\",\"value\":\"scope1\",\"restricted\":true,\"defaultScope\":false}," +
                "{\"id\":2,\"description\":\"Scope 2\",\"icon\":\"ball\",\"value\":\"scope2\",\"restricted\":false,\"defaultScope\":false}," +
                "{\"id\":3,\"description\":\"Scope 3\",\"icon\":\"road\",\"value\":\"scope3\",\"restricted\":false,\"defaultScope\":true}" +
                "  ]" +
                "}"

        logger.debug(configJson)

        dataService.importData(configJson)

        verify(sysScopeRepository, times(3)).save(capture(capturedScope))

        val savedScopes = capturedScope.allValues

        assertEquals(3, savedScopes.size)
        assertEquals(scope1.value, savedScopes[0].value)
        assertEquals(scope1.description, savedScopes[0].description)
        assertEquals(scope1.icon, savedScopes[0].icon)
        assertEquals(scope1.isDefaultScope, savedScopes[0].isDefaultScope)
        assertEquals(scope1.isRestricted, savedScopes[0].isRestricted)

        assertEquals(scope2.value, savedScopes[1].value)
        assertEquals(scope2.description, savedScopes[1].description)
        assertEquals(scope2.icon, savedScopes[1].icon)
        assertEquals(scope2.isDefaultScope, savedScopes[1].isDefaultScope)
        assertEquals(scope2.isRestricted, savedScopes[1].isRestricted)

        assertEquals(scope3.value, savedScopes[2].value)
        assertEquals(scope3.description, savedScopes[2].description)
        assertEquals(scope3.icon, savedScopes[2].icon)
        assertEquals(scope3.isDefaultScope, savedScopes[2].isDefaultScope)
        assertEquals(scope3.isRestricted, savedScopes[2].isRestricted)
    }

    @Test
    fun testExportAccessTokens() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
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

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
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
        assertTrue(root.contains(MITREidDataService.MITREID_CONNECT_1_3))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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

            var compare: OAuth2AccessTokenEntity? = null
            val tokenId = token["id"]!!.jsonPrimitive.long
            if (tokenId == token1.id) {
                compare = token1
            } else if (tokenId == token2.id) {
                compare = token2
            }

            if (compare == null) {
                fail("Could not find matching id: ${tokenId}")
            } else {
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
        }
        // make sure all of our access tokens were found
        assertTrue(checked.containsAll(allAccessTokens))
    }

    @Test
    @Throws(IOException::class)
    fun testExportClients() {
        val client1 = ClientDetailsEntity(
            id = 1L,
            accessTokenValiditySeconds = 3600,
            clientId = "client1",
            clientSecret = "clientsecret1",
            redirectUris = setOf("http://foo.com/"),
            scope = hashSetOf("foo", "bar", "baz", "dolphin"),
            authorizedGrantTypes = hashSetOf("implicit", "authorization_code", "urn:ietf:params:oauth:grant_type:redelegate", "refresh_token"),
            isAllowIntrospection = true,
        )

        val client2 = ClientDetailsEntity(
            id = 2L,
            accessTokenValiditySeconds = 3600,
            clientId = "client2",
            clientSecret = "clientsecret2",
            redirectUris = setOf("http://bar.baz.com/"),
            scope = hashSetOf("foo", "dolphin", "electric-wombat"),
            authorizedGrantTypes = hashSetOf("client_credentials", "urn:ietf:params:oauth:grant_type:redelegate"),
            isAllowIntrospection = false,
            codeChallengeMethod = PKCEAlgorithm.S256,
        )

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
        assertTrue(MITREidDataService.MITREID_CONNECT_1_3 in root)

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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
        assertTrue(MITREidDataService.MITREID_CONNECT_1_3 in root)

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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
                fail("Could not find matching blacklisted site id: " + site["id"].asString())
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
        assertTrue(root.contains(MITREidDataService.MITREID_CONNECT_1_3))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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
        assertTrue(root.contains(MITREidDataService.MITREID_CONNECT_1_3))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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
        val req1 = OAuth2Request(
            clientId = "client1",
            isApproved = true,
            redirectUri = "http://foo.com",
        )
        val mockAuth1: SavedUserAuthentication =  SavedUserAuthentication(name = "mockAuth1")
//            UsernamePasswordAuthenticationToken("user1", "pass1", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"))
        val auth1 = OAuth2RequestAuthentication(req1, mockAuth1)

        val holder1 = AuthenticationHolderEntity()
        holder1.id = 1L
        holder1.authentication = auth1

        val req2 = OAuth2Request(
            clientId = "client2",
            isApproved = true,
            redirectUri = "http://bar.com",
        )
        val auth2 = OAuth2RequestAuthentication(req2, null)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val allAuthHolders: List<AuthenticationHolderEntity> = listOf(holder1, holder2)

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
        assertTrue(root.contains(MITREidDataService.MITREID_CONNECT_1_3))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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
        val checked: MutableSet<AuthenticationHolderEntity> = HashSet()
        for (e in holders) {
            assertIs<JsonObject>(e)
            val holder = e.jsonObject

            var compare: AuthenticationHolderEntity? = null
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
                    val actualAuthenticated =  when(val a = savedAuth["authenticated"]) {
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
        assertTrue(MITREidDataService.MITREID_CONNECT_1_3 in root)

        val config = root[MITREidDataService.MITREID_CONNECT_1_3]!!.jsonObject

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

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val req1 = OAuth2Request(
            clientId = "client1",
            isApproved = true,
            redirectUri = "http://foo.com",
        )
        val mockAuth1 = SavedUserAuthentication(name = "mockAuth1")
        val auth1 = OAuth2RequestAuthentication(req1, mockAuth1)

        val holder1 = AuthenticationHolderEntity()
        holder1.id = 1L
        holder1.authentication = auth1

        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expirationInstant = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = holder1

        val expirationDate2 = instant("2015-01-07T18:31:50.079+00:00")

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val req2 = OAuth2Request(
            clientId = "client2",
            isApproved = true,
            redirectUri = "http://bar.com",
        )
        val mockAuth2 = SavedUserAuthentication(name = "mockAuth2")
        val auth2 = OAuth2RequestAuthentication(req2, mockAuth2)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val token2 = OAuth2RefreshTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expirationInstant = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.")
        token2.authenticationHolder = holder2

        val configJson = ("{" +
                "\"$SYSTEMSCOPES\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$CLIENTS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [" +
                "{\"id\":1,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]," +
                "\"$REFRESHTOKENS\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")
        logger.debug(configJson)

        val fakeRefreshTokenTable: MutableMap<Long, OAuth2RefreshTokenEntity> = HashMap()
        val fakeAuthHolderTable: MutableMap<Long, AuthenticationHolderEntity> = HashMap()
        whenever<OAuth2RefreshTokenEntity>(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2RefreshTokenEntity> {
                var id: Long = 343L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2RefreshTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2RefreshTokenEntity
                    val id = _token.id ?: id++.also { _token.id = it }
                    fakeRefreshTokenTable[id] = _token
                    return _token
                }
            })
        whenever(tokenRepository.getRefreshTokenById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeRefreshTokenTable[_id]
        }
        whenever(clientRepository.getClientByClientId(ArgumentMatchers.anyString())).thenAnswer { invocation ->
            val _clientId = invocation.arguments[0] as String
            val _client = mock<ClientDetailsEntity>()
            whenever(_client.clientId).thenReturn(_clientId)
            _client
        }
        whenever<AuthenticationHolderEntity>(authHolderRepository.save(isA<AuthenticationHolderEntity>()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 356L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _holder = invocation.arguments[0] as AuthenticationHolderEntity
                    val id = _holder.id ?: id++.also { _holder.id = it }
                    fakeAuthHolderTable[id] = _holder
                    return _holder
                }
            })
        whenever(authHolderRepository.getById(ArgumentMatchers.anyLong())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeAuthHolderTable[_id]
        }

        dataService.importData(configJson)

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> =
            fakeRefreshTokenTable.values.sortedWith(refreshTokenIdComparator())
        //capturedRefreshTokens.getAllValues();

        assertEquals(356L, savedRefreshTokens[0].authenticationHolder.id)
        assertEquals(357L, savedRefreshTokens[1].authenticationHolder.id)
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
