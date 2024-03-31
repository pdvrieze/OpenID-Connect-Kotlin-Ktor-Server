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
package org.mitre.openid.connect.service.impl

import com.google.gson.JsonArray
import com.google.gson.JsonParser
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import com.nimbusds.jwt.JWTParser
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.runner.RunWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.openid.connect.service.impl.MITREidDataService_1_3
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.Captor
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.MockitoJUnitRunner.Silent
import org.mockito.kotlin.capture
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.util.ReflectionUtils
import java.io.IOException
import java.io.StringReader
import java.io.StringWriter
import java.text.ParseException
import java.util.*

@RunWith(Silent::class)
class TestMITREidDataService_1_3 {
    @Mock
    private lateinit var clientRepository: OAuth2ClientRepository

    @Mock
    private lateinit var approvedSiteRepository: ApprovedSiteRepository

    @Mock
    private lateinit var wlSiteRepository: WhitelistedSiteRepository

    @Mock
    private lateinit var blSiteRepository: BlacklistedSiteRepository

    @Mock
    private lateinit var authHolderRepository: AuthenticationHolderRepository

    @Mock
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    private lateinit var sysScopeRepository: SystemScopeRepository

    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    @Captor
    private lateinit var capturedClients: ArgumentCaptor<ClientDetailsEntity>

    @Captor
    private lateinit var capturedBlacklistedSites: ArgumentCaptor<BlacklistedSite>

    @Captor
    private lateinit var capturedWhitelistedSites: ArgumentCaptor<WhitelistedSite>

    @Captor
    private lateinit var capturedApprovedSites: ArgumentCaptor<ApprovedSite>

    @Captor
    private lateinit var capturedAuthHolders: ArgumentCaptor<AuthenticationHolderEntity>

    @Captor
    private lateinit var capturedScope: ArgumentCaptor<SystemScope>

    @InjectMocks
    private lateinit var dataService: MITREidDataService_1_3
    private lateinit var formatter: DateFormatter

    private lateinit var maps: MITREidDataServiceMaps

    @Before
    fun prepare() {
        formatter = DateFormatter()
        formatter.setIso(DateTimeFormat.ISO.DATE_TIME)

        reset(clientRepository, approvedSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, wlSiteRepository, blSiteRepository)

        val mapsField = ReflectionUtils.findField(MITREidDataService_1_3::class.java, "maps")
        mapsField.isAccessible = true
        maps = ReflectionUtils.getField(mapsField, dataService) as MITREidDataServiceMaps
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testExportRefreshTokens() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = mockedAuthHolder1

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val token2 = OAuth2RefreshTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expiration = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.")
        token2.authenticationHolder = mockedAuthHolder2

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))


        // check our refresh token list (this test)
        val refreshTokens = config[MITREidDataService.REFRESHTOKENS].asJsonArray

        assertThat(refreshTokens.size(), CoreMatchers.`is`(2))
        // check for both of our refresh tokens in turn
        val checked: MutableSet<OAuth2RefreshTokenEntity> = HashSet()
        for (e in refreshTokens) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val token = e.asJsonObject

            var compare: OAuth2RefreshTokenEntity? = null
            if (token["id"].asLong == token1.id) {
                compare = token1
            } else if (token["id"].asLong == token2.id) {
                compare = token2
            }

            if (compare == null) {
                Assert.fail("Could not find matching id: " + token["id"].asString)
            } else {
                Assertions.assertEquals(compare.id, token["id"].asLong)
                Assertions.assertEquals(compare.client!!.clientId, token["clientId"].asString)
                Assertions.assertEquals(formatter.print(compare.expiration!!, Locale.ENGLISH), token["expiration"].asString)
                Assertions.assertEquals(compare.value, token["value"].asString)
                Assertions.assertEquals(compare.authenticationHolder.id, token["authenticationHolderId"].asLong)
                checked.add(compare)
            }
        }
        // make sure all of our refresh tokens were found
        assertThat(checked.containsAll(allRefreshTokens), CoreMatchers.`is`(true))
    }

    private inner class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }


    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportRefreshTokens() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = mockedAuthHolder1

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val token2 = OAuth2RefreshTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expiration = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.")
        token2.authenticationHolder = mockedAuthHolder2

        val configJson = ("{" +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")

        logger.debug(configJson)
        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, OAuth2RefreshTokenEntity> = HashMap()
        whenever<OAuth2RefreshTokenEntity>(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2RefreshTokenEntity> {
                var id: Long = 332L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2RefreshTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2RefreshTokenEntity
                    val id = _token.id ?: id++.also { _token.id = it }
                    fakeDb[id] = _token
                    return _token
                }
            })
        whenever(tokenRepository.getRefreshTokenById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeDb[_id]
        }
        whenever(clientRepository.getClientByClientId(ArgumentMatchers.anyString())).thenAnswer { invocation ->
            val _clientId = invocation.arguments[0] as String
            val _client = mock<ClientDetailsEntity>()
            whenever(_client.clientId).thenReturn(_clientId)
            _client
        }
        whenever(authHolderRepository.getById(ArgumentMatchers.isNull(Long::class.java)))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 131L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _auth = mock<AuthenticationHolderEntity>()
                    whenever(_auth.id).thenReturn(id)
                    id++
                    return _auth
                }
            })
        dataService.importData(reader)
        //2 times for token, 2 times to update client, 2 times to update authHolder
        verify(tokenRepository, times(6)).saveRefreshToken(capture(capturedRefreshTokens))

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> = fakeDb.values.sortedWith(refreshTokenIdComparator())
        ArrayList<Any>(fakeDb.values) //capturedRefreshTokens.getAllValues();
        Collections.sort(savedRefreshTokens, refreshTokenIdComparator())

        assertThat(savedRefreshTokens.size, CoreMatchers.`is`(2))

        Assertions.assertEquals(token1.client!!.clientId, savedRefreshTokens[0].client!!.clientId)
        Assertions.assertEquals(token1.expiration, savedRefreshTokens[0].expiration)
        Assertions.assertEquals(token1.value, savedRefreshTokens[0].value)

        Assertions.assertEquals(token2.client!!.clientId, savedRefreshTokens[1].client!!.clientId)
        Assertions.assertEquals(token2.expiration, savedRefreshTokens[1].expiration)
        Assertions.assertEquals(token2.value, savedRefreshTokens[1].value)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testExportAccessTokens() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2AccessTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0")
        token1.authenticationHolder = mockedAuthHolder1
        token1.scope = setOf("id-token")
        token1.tokenType = "Bearer"

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val mockRefreshToken2 = mock<OAuth2RefreshTokenEntity>()
        whenever(mockRefreshToken2.id).thenReturn(1L)

        val token2 = OAuth2AccessTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expiration = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ")
        token2.authenticationHolder = mockedAuthHolder2
        token2.refreshToken = mockRefreshToken2
        token2.scope = setOf("openid", "offline_access", "email", "profile")
        token2.tokenType = "Bearer"

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))


        // check our access token list (this test)
        val accessTokens = config[MITREidDataService.ACCESSTOKENS].asJsonArray

        assertThat(accessTokens.size(), CoreMatchers.`is`(2))
        // check for both of our access tokens in turn
        val checked: MutableSet<OAuth2AccessTokenEntity> = HashSet()
        for (e in accessTokens) {
            Assert.assertTrue(e.isJsonObject)
            val token = e.asJsonObject

            var compare: OAuth2AccessTokenEntity? = null
            if (token["id"].asLong == token1.id) {
                compare = token1
            } else if (token["id"].asLong == token2.id) {
                compare = token2
            }

            if (compare == null) {
                Assert.fail("Could not find matching id: " + token["id"].asString)
            } else {
                Assertions.assertEquals(compare.id, token["id"].asLong)
                Assertions.assertEquals(compare.client!!.clientId, token["clientId"].asString)
                Assertions.assertEquals(formatter.print(compare.expiration, Locale.ENGLISH), token["expiration"].asString)
                Assertions.assertEquals(compare.value, token["value"].asString)
                Assertions.assertEquals(compare.tokenType, token["type"].asString)
                Assertions.assertEquals(compare.authenticationHolder.id, token["authenticationHolderId"].asLong)
                Assert.assertTrue(token["scope"].isJsonArray)
                Assertions.assertEquals(compare.scope, jsonArrayToStringSet(token.getAsJsonArray("scope")))
                if (token["refreshTokenId"].isJsonNull) {
                    Assert.assertNull(compare.refreshToken)
                } else {
                    Assertions.assertEquals(compare.refreshToken!!.id, token["refreshTokenId"].asLong)
                }
                checked.add(compare)
            }
        }
        // make sure all of our access tokens were found
        assertThat(checked.containsAll(allAccessTokens), CoreMatchers.`is`(true))
    }

    private inner class accessTokenIdComparator : Comparator<OAuth2AccessTokenEntity> {
        override fun compare(entity1: OAuth2AccessTokenEntity, entity2: OAuth2AccessTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportAccessTokens() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder1.id).thenReturn(1L)

        val token1 = OAuth2AccessTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0")
        token1.authenticationHolder = mockedAuthHolder1
        token1.scope = setOf("id-token")
        token1.tokenType = "Bearer"

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()
        whenever(mockedAuthHolder2.id).thenReturn(2L)

        val mockRefreshToken2 = mock<OAuth2RefreshTokenEntity>()
        whenever(mockRefreshToken2.id).thenReturn(1L)

        val token2 = OAuth2AccessTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expiration = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ")
        token2.authenticationHolder = mockedAuthHolder2
        token2.refreshToken = mockRefreshToken2
        token2.scope = setOf("openid", "offline_access", "email", "profile")
        token2.tokenType = "Bearer"

        val configJson = ("{" +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"refreshTokenId\":null,\"idTokenId\":null,\"scope\":[\"id-token\"],\"type\":\"Bearer\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"refreshTokenId\":1,\"idTokenId\":1,\"scope\":[\"openid\",\"offline_access\",\"email\",\"profile\"],\"type\":\"Bearer\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ\"}" +
                "  ]" +
                "}")


        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, OAuth2AccessTokenEntity> = HashMap()
        whenever<OAuth2AccessTokenEntity>(tokenRepository.saveAccessToken(isA<OAuth2AccessTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2AccessTokenEntity> {
                var id: Long = 324L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2AccessTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2AccessTokenEntity
                    val id = _token.id ?: id++.also { _token.id = it }
                    fakeDb[id] = _token
                    return _token
                }
            })
        whenever(tokenRepository.getAccessTokenById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeDb[_id]
        }
        whenever(clientRepository.getClientByClientId(ArgumentMatchers.anyString())).thenAnswer { invocation ->
            val _clientId = invocation.arguments[0] as String
            val _client = mock<ClientDetailsEntity>()
            whenever(_client.clientId).thenReturn(_clientId)
            _client
        }
        whenever(authHolderRepository.getById(isA()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 133L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _auth = mock<AuthenticationHolderEntity>()
                    whenever(_auth.id).thenReturn(id)
                    id++
                    return _auth
                }
            })
        maps.refreshTokenOldToNewIdMap[1L] = 133L
        maps.authHolderOldToNewIdMap[1L] = 222L
        maps.authHolderOldToNewIdMap[2L] = 223L
        dataService.importData(reader)
        //2 times for token, 2 times to update client, 2 times to update authHolder, 1 times to update refresh token
        verify(tokenRepository, times(7)).saveAccessToken(capture(capturedAccessTokens))

        val savedAccessTokens: List<OAuth2AccessTokenEntity> = fakeDb.values.sortedWith(accessTokenIdComparator())
        //capturedAccessTokens.getAllValues();

        assertThat(savedAccessTokens.size, CoreMatchers.`is`(2))

        Assertions.assertEquals(token1.client!!.clientId, savedAccessTokens[0].client!!.clientId)
        Assertions.assertEquals(token1.expiration, savedAccessTokens[0].expiration)
        Assertions.assertEquals(token1.value, savedAccessTokens[0].value)

        Assertions.assertEquals(token2.client!!.clientId, savedAccessTokens[1].client!!.clientId)
        Assertions.assertEquals(token2.expiration, savedAccessTokens[1].expiration)
        Assertions.assertEquals(token2.value, savedAccessTokens[1].value)
    }

    @Test
    @Throws(IOException::class)
    fun testExportClients() {
        val client1 = ClientDetailsEntity()
        client1.id = 1L
        client1.accessTokenValiditySeconds = 3600
        client1.clientId = "client1"
        client1.clientSecret = "clientsecret1"
        client1.redirectUris = setOf("http://foo.com/")
        client1.setScope(setOf("foo", "bar", "baz", "dolphin"))
        client1.grantTypes =
            hashSetOf("implicit", "authorization_code", "urn:ietf:params:oauth:grant_type:redelegate", "refresh_token")
        client1.isAllowIntrospection = true

        val client2 = ClientDetailsEntity()
        client2.id = 2L
        client2.accessTokenValiditySeconds = 3600
        client2.clientId = "client2"
        client2.clientSecret = "clientsecret2"
        client2.redirectUris = setOf("http://bar.baz.com/")
        client2.setScope(setOf("foo", "dolphin", "electric-wombat"))
        client2.grantTypes = hashSetOf("client_credentials", "urn:ietf:params:oauth:grant_type:redelegate")
        client2.isAllowIntrospection = false
        client2.codeChallengeMethod = PKCEAlgorithm.S256

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))


        // check our client list (this test)
        val clients = config[MITREidDataService.CLIENTS].asJsonArray

        assertThat(clients.size(), CoreMatchers.`is`(2))
        // check for both of our clients in turn
        val checked: MutableSet<ClientDetailsEntity> = HashSet()
        for (e in clients) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val client = e.asJsonObject

            var compare: ClientDetailsEntity? = null
            if (client["clientId"].asString == client1.clientId) {
                compare = client1
            } else if (client["clientId"].asString == client2.clientId) {
                compare = client2
            }

            if (compare == null) {
                Assert.fail("Could not find matching clientId: " + client["clientId"].asString)
            } else {
                Assertions.assertEquals(compare.clientId, client["clientId"].asString)
                Assertions.assertEquals(compare.clientSecret, client["secret"].asString)
                Assertions.assertEquals(compare.accessTokenValiditySeconds, client["accessTokenValiditySeconds"].asInt)
                Assertions.assertEquals(compare.isAllowIntrospection, client["allowIntrospection"].asBoolean)
                Assertions.assertEquals(compare.redirectUris, jsonArrayToStringSet(client["redirectUris"].asJsonArray))
                Assertions.assertEquals(compare.scope, jsonArrayToStringSet(client["scope"].asJsonArray))
                Assertions.assertEquals(compare.grantTypes, jsonArrayToStringSet(client["grantTypes"].asJsonArray))
                Assertions.assertEquals(compare.codeChallengeMethod, if ((client.has("codeChallengeMethod") && !client["codeChallengeMethod"].isJsonNull)) parse(client["codeChallengeMethod"].asString) else null)
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allClients), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class)
    fun testImportClients() {
        val client1 = ClientDetailsEntity()
        client1.id = 1L
        client1.accessTokenValiditySeconds = 3600
        client1.clientId = "client1"
        client1.clientSecret = "clientsecret1"
        client1.redirectUris = setOf("http://foo.com/")
        client1.setScope(setOf("foo", "bar", "baz", "dolphin"))
        client1.grantTypes =
            hashSetOf("implicit", "authorization_code", "urn:ietf:params:oauth:grant_type:redelegate", "refresh_token")
        client1.isAllowIntrospection = true

        val client2 = ClientDetailsEntity()
        client2.id = 2L
        client2.accessTokenValiditySeconds = 3600
        client2.clientId = "client2"
        client2.clientSecret = "clientsecret2"
        client2.redirectUris = setOf("http://bar.baz.com/")
        client2.setScope(setOf("foo", "dolphin", "electric-wombat"))
        client2.grantTypes = hashSetOf("client_credentials", "urn:ietf:params:oauth:grant_type:redelegate")
        client2.isAllowIntrospection = false

        val configJson = ("{" +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.CLIENTS + "\": [" +
                "{\"id\":1,\"accessTokenValiditySeconds\":3600,\"clientId\":\"client1\",\"secret\":\"clientsecret1\","
                + "\"redirectUris\":[\"http://foo.com/\"],"
                + "\"scope\":[\"foo\",\"bar\",\"baz\",\"dolphin\"],"
                + "\"grantTypes\":[\"implicit\",\"authorization_code\",\"urn:ietf:params:oauth:grant_type:redelegate\",\"refresh_token\"],"
                + "\"allowIntrospection\":true}," +
                "{\"id\":2,\"accessTokenValiditySeconds\":3600,\"clientId\":\"client2\",\"secret\":\"clientsecret2\","
                + "\"redirectUris\":[\"http://bar.baz.com/\"],"
                + "\"scope\":[\"foo\",\"dolphin\",\"electric-wombat\"],"
                + "\"grantTypes\":[\"client_credentials\",\"urn:ietf:params:oauth:grant_type:redelegate\"],"
                + "\"allowIntrospection\":false}" +
                "  ]" +
                "}")

        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(clientRepository, times(2)).saveClient(capture(capturedClients))

        val savedClients = capturedClients.allValues

        assertThat(savedClients.size, CoreMatchers.`is`(2))

        Assertions.assertEquals(client1.accessTokenValiditySeconds, savedClients[0].accessTokenValiditySeconds)
        Assertions.assertEquals(client1.clientId, savedClients[0].clientId)
        Assertions.assertEquals(client1.clientSecret, savedClients[0].clientSecret)
        Assertions.assertEquals(client1.redirectUris, savedClients[0].redirectUris)
        Assertions.assertEquals(client1.scope, savedClients[0].scope)
        Assertions.assertEquals(client1.grantTypes, savedClients[0].grantTypes)
        Assertions.assertEquals(client1.isAllowIntrospection, savedClients[0].isAllowIntrospection)

        Assertions.assertEquals(client2.accessTokenValiditySeconds, savedClients[1].accessTokenValiditySeconds)
        Assertions.assertEquals(client2.clientId, savedClients[1].clientId)
        Assertions.assertEquals(client2.clientSecret, savedClients[1].clientSecret)
        Assertions.assertEquals(client2.redirectUris, savedClients[1].redirectUris)
        Assertions.assertEquals(client2.scope, savedClients[1].scope)
        Assertions.assertEquals(client2.grantTypes, savedClients[1].grantTypes)
        Assertions.assertEquals(client2.isAllowIntrospection, savedClients[1].isAllowIntrospection)
    }

    @Test
    @Throws(IOException::class)
    fun testExportBlacklistedSites() {
        val site1 = BlacklistedSite()
        site1.id = 1L
        site1.uri = "http://foo.com"

        val site2 = BlacklistedSite()
        site2.id = 2L
        site2.uri = "http://bar.com"

        val site3 = BlacklistedSite()
        site3.id = 3L
        site3.uri = "http://baz.com"

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))

        // check our scope list (this test)
        val sites = config[MITREidDataService.BLACKLISTEDSITES].asJsonArray

        assertThat(sites.size(), CoreMatchers.`is`(3))
        // check for both of our sites in turn
        val checked: MutableSet<BlacklistedSite> = HashSet()
        for (e in sites) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val site = e.asJsonObject

            var compare: BlacklistedSite? = null
            if (site["id"].asLong == site1.id) {
                compare = site1
            } else if (site["id"].asLong == site2.id) {
                compare = site2
            } else if (site["id"].asLong == site3.id) {
                compare = site3
            }

            if (compare == null) {
                Assert.fail("Could not find matching blacklisted site id: " + site["id"].asString)
            } else {
                Assertions.assertEquals(compare.uri, site["uri"].asString)
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allBlacklistedSites), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class)
    fun testImportBlacklistedSites() {
        val site1 = BlacklistedSite()
        site1.id = 1L
        site1.uri = "http://foo.com"

        val site2 = BlacklistedSite()
        site2.id = 2L
        site2.uri = "http://bar.com"

        val site3 = BlacklistedSite()
        site3.id = 3L
        site3.uri = "http://baz.com"

        val configJson = "{" +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [" +
                "{\"id\":1,\"uri\":\"http://foo.com\"}," +
                "{\"id\":2,\"uri\":\"http://bar.com\"}," +
                "{\"id\":3,\"uri\":\"http://baz.com\"}" +
                "  ]" +
                "}"


        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(blSiteRepository, times(3)).save(capture(capturedBlacklistedSites))

        val savedSites = capturedBlacklistedSites.allValues

        assertThat(savedSites.size, CoreMatchers.`is`(3))

        Assertions.assertEquals(site1.uri, savedSites[0].uri)
        Assertions.assertEquals(site2.uri, savedSites[1].uri)
        Assertions.assertEquals(site3.uri, savedSites[2].uri)
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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))

        // check our scope list (this test)
        val sites = config[MITREidDataService.WHITELISTEDSITES].asJsonArray

        assertThat(sites.size(), CoreMatchers.`is`(3))
        // check for both of our sites in turn
        val checked: MutableSet<WhitelistedSite> = HashSet()
        for (e in sites) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val site = e.asJsonObject

            var compare: WhitelistedSite? = null
            if (site["id"].asLong == site1.id) {
                compare = site1
            } else if (site["id"].asLong == site2.id) {
                compare = site2
            } else if (site["id"].asLong == site3.id) {
                compare = site3
            }

            if (compare == null) {
                Assert.fail("Could not find matching whitelisted site id: " + site["id"].asString)
            } else {
                Assertions.assertEquals(compare.clientId, site["clientId"].asString)
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allWhitelistedSites), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class)
    fun testImportWhitelistedSites() {
        val site1 = WhitelistedSite()
        site1.id = 1L
        site1.clientId = "foo"

        val site2 = WhitelistedSite()
        site2.id = 2L
        site2.clientId = "bar"

        val site3 = WhitelistedSite()
        site3.id = 3L
        site3.clientId = "baz"

        //site3.setAllowedScopes(null);
        val configJson = "{" +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [" +
                "{\"id\":1,\"clientId\":\"foo\"}," +
                "{\"id\":2,\"clientId\":\"bar\"}," +
                "{\"id\":3,\"clientId\":\"baz\"}" +
                "  ]" +
                "}"

        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, WhitelistedSite> = HashMap()
        whenever<WhitelistedSite>(wlSiteRepository.save(isA<WhitelistedSite>()))
            .thenAnswer(object : Answer<WhitelistedSite> {
                var id: Long = 333L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): WhitelistedSite {
                    val _site = invocation.arguments[0] as WhitelistedSite
                    val id = _site.id ?: id++.also { _site.id = it }
                    fakeDb[id] = _site
                    return _site
                }
            })
        whenever(wlSiteRepository.getById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeDb[_id]
        }

        dataService.importData(reader)
        verify(wlSiteRepository, times(3)).save(capture(capturedWhitelistedSites))

        val savedSites = capturedWhitelistedSites.allValues

        assertThat(savedSites.size, CoreMatchers.`is`(3))

        Assertions.assertEquals(site1.clientId, savedSites[0].clientId)
        Assertions.assertEquals(site2.clientId, savedSites[1].clientId)
        Assertions.assertEquals(site3.clientId, savedSites[2].clientId)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testExportGrants() {
        val creationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)
        val accessDate1 = formatter.parse("2014-09-10T23:49:44.090+00:00", Locale.ENGLISH)

        val mockToken1 = mock<OAuth2AccessTokenEntity>()
        whenever(mockToken1.id).thenReturn(1L)

        val site1 = ApprovedSite()
        site1.id = 1L
        site1.clientId = "foo"
        site1.creationDate = creationDate1
        site1.accessDate = accessDate1
        site1.userId = "user1"
        site1.allowedScopes = setOf("openid", "phone")
        whenever(mockToken1.approvedSite).thenReturn(site1)

        val creationDate2 = formatter.parse("2014-09-11T18:49:44.090+00:00", Locale.ENGLISH)
        val accessDate2 = formatter.parse("2014-09-11T20:49:44.090+00:00", Locale.ENGLISH)
        val timeoutDate2 = formatter.parse("2014-10-01T20:49:44.090+00:00", Locale.ENGLISH)

        val site2 = ApprovedSite()
        site2.id = 2L
        site2.clientId = "bar"
        site2.creationDate = creationDate2
        site2.accessDate = accessDate2
        site2.userId = "user2"
        site2.allowedScopes = setOf("openid", "offline_access", "email", "profile")
        site2.timeoutDate = timeoutDate2

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))

        // check our scope list (this test)
        val sites = config[MITREidDataService.GRANTS].asJsonArray

        assertThat(sites.size(), CoreMatchers.`is`(2))
        // check for both of our sites in turn
        val checked: MutableSet<ApprovedSite> = HashSet()
        for (e in sites) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val site = e.asJsonObject

            var compare: ApprovedSite? = null
            if (site["id"].asLong == site1.id) {
                compare = site1
            } else if (site["id"].asLong == site2.id) {
                compare = site2
            }

            if (compare == null) {
                Assert.fail("Could not find matching whitelisted site id: " + site["id"].asString)
            } else {
                Assertions.assertEquals(compare.clientId, site["clientId"].asString)
                Assertions.assertEquals(formatter.print(compare.creationDate, Locale.ENGLISH), site["creationDate"].asString)
                Assertions.assertEquals(formatter.print(compare.accessDate, Locale.ENGLISH), site["accessDate"].asString)
                if (site["timeoutDate"].isJsonNull) {
                    Assert.assertNull(compare.timeoutDate)
                } else {
                    Assertions.assertEquals(formatter.print(compare.timeoutDate, Locale.ENGLISH), site["timeoutDate"].asString)
                }
                Assertions.assertEquals(compare.userId, site["userId"].asString)
                Assertions.assertEquals(compare.allowedScopes, jsonArrayToStringSet(site.getAsJsonArray("allowedScopes")))
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allApprovedSites), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportGrants() {
        val creationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)
        val accessDate1 = formatter.parse("2014-09-10T23:49:44.090+00:00", Locale.ENGLISH)

        val mockToken1 = mock<OAuth2AccessTokenEntity>()
        whenever(mockToken1.id).thenReturn(1L)

        val site1 = ApprovedSite()
        site1.id = 1L
        site1.clientId = "foo"
        site1.creationDate = creationDate1
        site1.accessDate = accessDate1
        site1.userId = "user1"
        site1.allowedScopes = setOf("openid", "phone")
        whenever(mockToken1.approvedSite).thenReturn(site1)

        val creationDate2 = formatter.parse("2014-09-11T18:49:44.090+00:00", Locale.ENGLISH)
        val accessDate2 = formatter.parse("2014-09-11T20:49:44.090+00:00", Locale.ENGLISH)
        val timeoutDate2 = formatter.parse("2014-10-01T20:49:44.090+00:00", Locale.ENGLISH)

        val site2 = ApprovedSite()
        site2.id = 2L
        site2.clientId = "bar"
        site2.creationDate = creationDate2
        site2.accessDate = accessDate2
        site2.userId = "user2"
        site2.allowedScopes = setOf("openid", "offline_access", "email", "profile")
        site2.timeoutDate = timeoutDate2

        val configJson = ("{" +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [" +
                "{\"id\":1,\"clientId\":\"foo\",\"creationDate\":\"2014-09-10T22:49:44.090+00:00\",\"accessDate\":\"2014-09-10T23:49:44.090+00:00\","
                + "\"userId\":\"user1\",\"whitelistedSiteId\":null,\"allowedScopes\":[\"openid\",\"phone\"], \"whitelistedSiteId\":1,"
                + "\"approvedAccessTokens\":[1]}," +
                "{\"id\":2,\"clientId\":\"bar\",\"creationDate\":\"2014-09-11T18:49:44.090+00:00\",\"accessDate\":\"2014-09-11T20:49:44.090+00:00\","
                + "\"timeoutDate\":\"2014-10-01T20:49:44.090+00:00\",\"userId\":\"user2\","
                + "\"allowedScopes\":[\"openid\",\"offline_access\",\"email\",\"profile\"]}" +
                "  ]" +
                "}")

        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, ApprovedSite> = HashMap()
        whenever<ApprovedSite>(approvedSiteRepository.save(isA<ApprovedSite>()))
            .thenAnswer(object : Answer<ApprovedSite> {
                var id: Long = 364L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): ApprovedSite {
                    val _site = invocation.arguments[0] as ApprovedSite
                    val id = _site.id ?: id++.also { _site.id = it }
                    fakeDb[id] = _site
                    return _site
                }
            })
        whenever(approvedSiteRepository.getById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeDb[_id]
        }
        whenever(wlSiteRepository.getById(isA()))
            .thenAnswer(object : Answer<WhitelistedSite> {
                var id: Long = 432L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): WhitelistedSite {
                    val _site = mock<WhitelistedSite>()
                    whenever(_site.id).thenReturn(id++)
                    return _site
                }
            })
        whenever(tokenRepository.getAccessTokenById(isA()))
            .thenAnswer(object : Answer<OAuth2AccessTokenEntity> {
                var id: Long = 245L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2AccessTokenEntity {
                    val _token = mock<OAuth2AccessTokenEntity>()
                    whenever(_token.id).thenReturn(id++)
                    return _token
                }
            })

        maps.accessTokenOldToNewIdMap[1L] = 245L
        dataService.importData(reader)
        //2 for sites, 1 for updating access token ref on #1
        verify(approvedSiteRepository, times(3)).save(capture(capturedApprovedSites))

        val savedSites: List<ApprovedSite> = fakeDb.values.toList()

        assertThat(savedSites.size, CoreMatchers.`is`(2))

        Assertions.assertEquals(site1.clientId, savedSites[0].clientId)
        Assertions.assertEquals(site1.accessDate, savedSites[0].accessDate)
        Assertions.assertEquals(site1.creationDate, savedSites[0].creationDate)
        Assertions.assertEquals(site1.allowedScopes, savedSites[0].allowedScopes)
        Assertions.assertEquals(site1.timeoutDate, savedSites[0].timeoutDate)

        Assertions.assertEquals(site2.clientId, savedSites[1].clientId)
        Assertions.assertEquals(site2.accessDate, savedSites[1].accessDate)
        Assertions.assertEquals(site2.creationDate, savedSites[1].creationDate)
        Assertions.assertEquals(site2.allowedScopes, savedSites[1].allowedScopes)
        Assertions.assertEquals(site2.timeoutDate, savedSites[1].timeoutDate)
    }

    @Test
    @Throws(IOException::class)
    fun testExportAuthenticationHolders() {
        val req1 = OAuth2Request(
            HashMap(), "client1", ArrayList(),
            true, HashSet(), HashSet(), "http://foo.com",
            HashSet(), null
        )
        val mockAuth1: Authentication =
            UsernamePasswordAuthenticationToken("user1", "pass1", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"))
        val auth1 = OAuth2Authentication(req1, mockAuth1)

        val holder1 = AuthenticationHolderEntity()
        holder1.id = 1L
        holder1.authentication = auth1

        val req2 = OAuth2Request(
            HashMap(), "client2", ArrayList(),
            true, HashSet(), HashSet(), "http://bar.com",
            HashSet(), null
        )
        val auth2 = OAuth2Authentication(req2, null)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val allAuthHolders: List<AuthenticationHolderEntity> = listOf(holder1,holder2)

        whenever(clientRepository.allClients).thenReturn(HashSet())
        whenever(approvedSiteRepository.all).thenReturn(HashSet())
        whenever(wlSiteRepository.all).thenReturn(HashSet())
        whenever(blSiteRepository.all).thenReturn(HashSet())
        whenever(authHolderRepository.all).thenReturn(allAuthHolders)
        whenever(tokenRepository.allAccessTokens).thenReturn(HashSet())
        whenever(tokenRepository.allRefreshTokens).thenReturn(HashSet())
        whenever(sysScopeRepository.all).thenReturn(HashSet())

        // do the data export
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))


        // check our holder list (this test)
        val holders = config[MITREidDataService.AUTHENTICATIONHOLDERS].asJsonArray

        assertThat(holders.size(), CoreMatchers.`is`(2))
        // check for both of our clients in turn
        val checked: MutableSet<AuthenticationHolderEntity> = HashSet()
        for (e in holders) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val holder = e.asJsonObject

            var compare: AuthenticationHolderEntity? = null
            if (holder["id"].asLong == holder1.id) {
                compare = holder1
            } else if (holder["id"].asLong == holder2.id) {
                compare = holder2
            }

            if (compare == null) {
                Assert.fail("Could not find matching authentication holder id: " + holder["id"].asString)
            } else {
                Assert.assertTrue(holder["clientId"].asString == compare.clientId)
                Assert.assertTrue(holder["approved"].asBoolean == compare.isApproved)
                Assert.assertTrue(holder["redirectUri"].asString == compare.redirectUri)
                if (compare.userAuth != null) {
                    Assert.assertTrue(holder["savedUserAuthentication"].isJsonObject)
                    val savedAuth = holder["savedUserAuthentication"].asJsonObject
                    Assert.assertTrue(savedAuth["name"].asString == compare.userAuth!!.name)
                    Assert.assertTrue(savedAuth["authenticated"].asBoolean == compare.userAuth!!.isAuthenticated)
                    Assert.assertTrue(savedAuth["sourceClass"].asString == compare.userAuth!!.sourceClass)
                }
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allAuthHolders), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class)
    fun testImportAuthenticationHolders() {
        val req1 = OAuth2Request(
            HashMap(), "client1", ArrayList(),
            true, HashSet(), HashSet(), "http://foo.com",
            HashSet(), null
        )
        val mockAuth1 = mock<Authentication>(serializable = true)
        val auth1 = OAuth2Authentication(req1, mockAuth1)

        val holder1 = AuthenticationHolderEntity()
        holder1.id = 1L
        holder1.authentication = auth1

        val req2 = OAuth2Request(
            HashMap(), "client2", ArrayList(),
            true, HashSet(), HashSet(), "http://bar.com",
            HashSet(), null
        )
        val mockAuth2 = mock<Authentication>(serializable = true)
        val auth2 = OAuth2Authentication(req2, mockAuth2)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val configJson = ("{" +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [" +
                "{\"id\":1,\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\","
                + "\"savedUserAuthentication\":null}," +
                "{\"id\":2,\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\","
                + "\"savedUserAuthentication\":null}" +
                "  ]" +
                "}")

        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, AuthenticationHolderEntity> = HashMap()
        whenever<AuthenticationHolderEntity>(authHolderRepository.save(isA<AuthenticationHolderEntity>()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 243L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _site = invocation.arguments[0] as AuthenticationHolderEntity
                    val id = _site.id ?: id++.also { _site.id = it }
                    fakeDb[id] = _site
                    return _site
                }
            })

        dataService.importData(reader)
        verify(authHolderRepository, times(2)).save(capture(capturedAuthHolders))

        val savedAuthHolders = capturedAuthHolders.allValues

        assertThat(savedAuthHolders.size, CoreMatchers.`is`(2))
        Assertions.assertEquals(holder1.authentication.oAuth2Request.clientId, savedAuthHolders[0].authentication.oAuth2Request.clientId)
        Assertions.assertEquals(holder2.authentication.oAuth2Request.clientId, savedAuthHolders[1].authentication.oAuth2Request.clientId)
    }

    @Test
    @Throws(IOException::class)
    fun testExportSystemScopes() {
        val scope1 = SystemScope()
        scope1.id = 1L
        scope1.value = "scope1"
        scope1.description = "Scope 1"
        scope1.isRestricted = true
        scope1.isDefaultScope = false
        scope1.icon = "glass"

        val scope2 = SystemScope()
        scope2.id = 2L
        scope2.value = "scope2"
        scope2.description = "Scope 2"
        scope2.isRestricted = false
        scope2.isDefaultScope = false
        scope2.icon = "ball"

        val scope3 = SystemScope()
        scope3.id = 3L
        scope3.value = "scope3"
        scope3.description = "Scope 3"
        scope3.isRestricted = false
        scope3.isDefaultScope = true
        scope3.icon = "road"

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
        val stringWriter = StringWriter()
        val writer = JsonWriter(stringWriter)
        writer.beginObject()
        dataService.exportData(writer)
        writer.endObject()
        writer.close()

        // parse the output as a JSON object for testing
        val elem = JsonParser().parse(stringWriter.toString())
        val root = elem.asJsonObject

        // make sure the root is there
        assertThat(root.has(MITREidDataService.MITREID_CONNECT_1_3), CoreMatchers.`is`(true))

        val config = root[MITREidDataService.MITREID_CONNECT_1_3].asJsonObject

        // make sure all the root elements are there
        assertThat(config.has(MITREidDataService.CLIENTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.GRANTS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.WHITELISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.BLACKLISTEDSITES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.REFRESHTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.ACCESSTOKENS), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.SYSTEMSCOPES), CoreMatchers.`is`(true))
        assertThat(config.has(MITREidDataService.AUTHENTICATIONHOLDERS), CoreMatchers.`is`(true))

        // make sure the root elements are all arrays
        assertThat(config[MITREidDataService.CLIENTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.GRANTS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.WHITELISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.BLACKLISTEDSITES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.REFRESHTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.ACCESSTOKENS].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.SYSTEMSCOPES].isJsonArray, CoreMatchers.`is`(true))
        assertThat(config[MITREidDataService.AUTHENTICATIONHOLDERS].isJsonArray, CoreMatchers.`is`(true))


        // check our scope list (this test)
        val scopes = config[MITREidDataService.SYSTEMSCOPES].asJsonArray

        assertThat(scopes.size(), CoreMatchers.`is`(3))
        // check for both of our clients in turn
        val checked: MutableSet<SystemScope> = HashSet()
        for (e in scopes) {
            assertThat(e.isJsonObject, CoreMatchers.`is`(true))
            val scope = e.asJsonObject

            var compare: SystemScope? = null
            if (scope["value"].asString == scope1.value) {
                compare = scope1
            } else if (scope["value"].asString == scope2.value) {
                compare = scope2
            } else if (scope["value"].asString == scope3.value) {
                compare = scope3
            }

            if (compare == null) {
                Assert.fail("Could not find matching scope value: " + scope["value"].asString)
            } else {
                Assertions.assertEquals(compare.value, scope["value"].asString)
                Assertions.assertEquals(compare.description, scope["description"].asString)
                Assertions.assertEquals(compare.icon, scope["icon"].asString)
                Assertions.assertEquals(compare.isRestricted, scope["restricted"].asBoolean)
                Assertions.assertEquals(compare.isDefaultScope, scope["defaultScope"].asBoolean)
                checked.add(compare)
            }
        }
        // make sure all of our clients were found
        assertThat(checked.containsAll(allScopes), CoreMatchers.`is`(true))
    }

    @Test
    @Throws(IOException::class)
    fun testImportSystemScopes() {
        val scope1 = SystemScope()
        scope1.id = 1L
        scope1.value = "scope1"
        scope1.description = "Scope 1"
        scope1.isRestricted = true
        scope1.isDefaultScope = false
        scope1.icon = "glass"

        val scope2 = SystemScope()
        scope2.id = 2L
        scope2.value = "scope2"
        scope2.description = "Scope 2"
        scope2.isRestricted = false
        scope2.isDefaultScope = false
        scope2.icon = "ball"

        val scope3 = SystemScope()
        scope3.id = 3L
        scope3.value = "scope3"
        scope3.description = "Scope 3"
        scope3.isRestricted = false
        scope3.isDefaultScope = true
        scope3.icon = "road"

        val configJson = "{" +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [" +
                "{\"id\":1,\"description\":\"Scope 1\",\"icon\":\"glass\",\"value\":\"scope1\",\"restricted\":true,\"defaultScope\":false}," +
                "{\"id\":2,\"description\":\"Scope 2\",\"icon\":\"ball\",\"value\":\"scope2\",\"restricted\":false,\"defaultScope\":false}," +
                "{\"id\":3,\"description\":\"Scope 3\",\"icon\":\"road\",\"value\":\"scope3\",\"restricted\":false,\"defaultScope\":true}" +
                "  ]" +
                "}"

        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(sysScopeRepository, times(3)).save(capture(capturedScope))

        val savedScopes = capturedScope.allValues

        assertThat(savedScopes.size, CoreMatchers.`is`(3))
        Assertions.assertEquals(scope1.value, savedScopes[0].value)
        Assertions.assertEquals(scope1.description, savedScopes[0].description)
        Assertions.assertEquals(scope1.icon, savedScopes[0].icon)
        Assertions.assertEquals(scope1.isDefaultScope, savedScopes[0].isDefaultScope)
        Assertions.assertEquals(scope1.isRestricted, savedScopes[0].isRestricted)

        Assertions.assertEquals(scope2.value, savedScopes[1].value)
        Assertions.assertEquals(scope2.description, savedScopes[1].description)
        Assertions.assertEquals(scope2.icon, savedScopes[1].icon)
        Assertions.assertEquals(scope2.isDefaultScope, savedScopes[1].isDefaultScope)
        Assertions.assertEquals(scope2.isRestricted, savedScopes[1].isRestricted)

        Assertions.assertEquals(scope3.value, savedScopes[2].value)
        Assertions.assertEquals(scope3.description, savedScopes[2].description)
        Assertions.assertEquals(scope3.icon, savedScopes[2].icon)
        Assertions.assertEquals(scope3.isDefaultScope, savedScopes[2].isDefaultScope)
        Assertions.assertEquals(scope3.isRestricted, savedScopes[2].isRestricted)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val req1 = OAuth2Request(
            HashMap(), "client1", ArrayList(),
            true, HashSet(), HashSet(), "http://foo.com",
            HashSet(), null
        )
        val mockAuth1 = mock<Authentication>(serializable = true)
        val auth1 = OAuth2Authentication(req1, mockAuth1)

        val holder1 = AuthenticationHolderEntity()
        holder1.id = 1L
        holder1.authentication = auth1

        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = holder1

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val req2 = OAuth2Request(
            HashMap(), "client2", ArrayList(),
            true, HashSet(), HashSet(), "http://bar.com",
            HashSet(), null
        )
        val mockAuth2 = mock<Authentication>(serializable = true)
        val auth2 = OAuth2Authentication(req2, mockAuth2)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val token2 = OAuth2RefreshTokenEntity()
        token2.id = 2L
        token2.client = mockedClient2
        token2.expiration = expirationDate2
        token2.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.")
        token2.authenticationHolder = holder2

        val configJson = ("{" +
                "\"" + MITREidDataService.SYSTEMSCOPES + "\": [], " +
                "\"" + MITREidDataService.ACCESSTOKENS + "\": [], " +
                "\"" + MITREidDataService.CLIENTS + "\": [], " +
                "\"" + MITREidDataService.GRANTS + "\": [], " +
                "\"" + MITREidDataService.WHITELISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.BLACKLISTEDSITES + "\": [], " +
                "\"" + MITREidDataService.AUTHENTICATIONHOLDERS + "\": [" +
                "{\"id\":1,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]," +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")
        logger.debug(configJson)

        val reader = JsonReader(StringReader(configJson))
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
        dataService.importData(reader)

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> =
            fakeRefreshTokenTable.values.sortedWith(refreshTokenIdComparator())
        //capturedRefreshTokens.getAllValues();

        Assertions.assertEquals(356L, savedRefreshTokens[0].authenticationHolder.id)
        Assertions.assertEquals(357L, savedRefreshTokens[1].authenticationHolder.id)
    }

    private fun jsonArrayToStringSet(a: JsonArray): Set<String> {
        val s: MutableSet<String> = HashSet()
        for (jsonElement in a) {
            s.add(jsonElement.asString)
        }
        return s
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(TestMITREidDataService_1_3::class.java)
    }
}
