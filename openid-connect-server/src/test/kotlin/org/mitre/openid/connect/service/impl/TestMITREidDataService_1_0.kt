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
package org.mitre.openid.connect.service.impl

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import com.nimbusds.jwt.JWTParser
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions
import org.junit.runner.RunWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.util.toJavaId
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.Captor
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.MockitoJUnitRunner
import org.mockito.kotlin.capture
import org.mockito.kotlin.eq
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.util.ReflectionUtils
import java.io.IOException
import java.io.StringReader
import java.io.StringWriter
import java.text.ParseException
import java.util.*

@RunWith(MockitoJUnitRunner::class)
class TestMITREidDataService_1_0 {
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
    private lateinit var dataService: MITREidDataService_1_0

    private lateinit var formatter: DateFormatter

    private lateinit var maps: MITREidDataServiceMaps

    @Before
    fun prepare() {
        formatter = DateFormatter()
        formatter.setIso(DateTimeFormat.ISO.DATE_TIME)
        reset(clientRepository, approvedSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, wlSiteRepository, blSiteRepository)
        val mapsField = ReflectionUtils.findField(MITREidDataService_1_0::class.java, "maps")!!
        mapsField.isAccessible = true
        maps = ReflectionUtils.getField(mapsField, dataService) as MITREidDataServiceMaps
    }

    private inner class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportRefreshTokens() {
        val expirationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedAuthHolder1.getId()).thenReturn(1L);
        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expiration = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = mockedAuthHolder1

        val expirationDate2 = formatter.parse("2015-01-07T18:31:50.079+00:00", Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedAuthHolder2.getId()).thenReturn(2L);
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

        System.err.println(configJson)
        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, OAuth2RefreshTokenEntity> = HashMap()
        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2RefreshTokenEntity> {
                var id: Long = 343L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2RefreshTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2RefreshTokenEntity
                    val id: Long = _token.id ?: (id++).also { _token.id = it }
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
                var id: Long = 678L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _auth = mock<AuthenticationHolderEntity>()
                    // unused by mockito (causs unnecessary stubbing exception
//				when(_auth.getId()).thenReturn(id);
                    id++
                    return _auth
                }
            })
        dataService.importData(reader)
        //2 times for token, 2 times to update client, 2 times to update authHolder
        verify(tokenRepository, times(6)).saveRefreshToken(capture(capturedRefreshTokens))

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> = fakeDb.values.sortedWith(refreshTokenIdComparator())
        //capturedRefreshTokens.getAllValues();

        Assertions.assertEquals(2, savedRefreshTokens.size)

        Assertions.assertEquals(token1.client!!.clientId, savedRefreshTokens[0].client!!.clientId)
        Assertions.assertEquals(token1.expiration, savedRefreshTokens[0].expiration)
        Assertions.assertEquals(token1.value, savedRefreshTokens[0].value)

        Assertions.assertEquals(token2.client!!.clientId, savedRefreshTokens[1].client!!.clientId)
        Assertions.assertEquals(token2.expiration, savedRefreshTokens[1].expiration)
        Assertions.assertEquals(token2.value, savedRefreshTokens[1].value)
    }

    private inner class accessTokenIdComparator : Comparator<OAuth2AccessTokenEntity> {
        override fun compare(entity1: OAuth2AccessTokenEntity, entity2: OAuth2AccessTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportAccessTokens() {
        val expirationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedAuthHolder1.getId()).thenReturn(1L);
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

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedAuthHolder2.getId()).thenReturn(2L);
        val mockRefreshToken2 = mock<OAuth2RefreshTokenEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockRefreshToken2.getId()).thenReturn(1L);
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


        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, OAuth2AccessTokenEntity> = HashMap()
        whenever<OAuth2AccessTokenEntity>(tokenRepository.saveAccessToken(isA<OAuth2AccessTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2AccessTokenEntity> {
                var id: Long = 343L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2AccessTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2AccessTokenEntity
                    val id = _token.id ?: (id++).also { _token.id = it }
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
        whenever(authHolderRepository.getById(ArgumentMatchers.argThat { x: Long? -> true }))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 234L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _auth = mock<AuthenticationHolderEntity>()
                    // unused by mockito (causs unnecessary stubbing exception
//				when(_auth.getId()).thenReturn(id);
                    id++
                    return _auth
                }
            })
        maps.authHolderOldToNewIdMap[1L] = 401L
        maps.authHolderOldToNewIdMap[1L] = 403L
        maps.refreshTokenOldToNewIdMap[1L] = 402L
        dataService.importData(reader)
        //2 times for token, 2 times to update client, 2 times to update authHolder, 1 times to update refresh token
        verify(tokenRepository, times(7)).saveAccessToken(capture(capturedAccessTokens))

        val savedAccessTokens: List<OAuth2AccessTokenEntity> = fakeDb.values.sortedWith(accessTokenIdComparator())

        Assertions.assertEquals(2, savedAccessTokens.size)

        Assertions.assertEquals(token1.client!!.clientId, savedAccessTokens[0].client!!.clientId)
        Assertions.assertEquals(token1.expiration, savedAccessTokens[0].expiration)
        Assertions.assertEquals(token1.value, savedAccessTokens[0].value)

        Assertions.assertEquals(token2.client!!.clientId, savedAccessTokens[1].client!!.clientId)
        Assertions.assertEquals(token2.expiration, savedAccessTokens[1].expiration)
        Assertions.assertEquals(token2.value, savedAccessTokens[1].value)
    }


    //several new client fields added in 1.1, perhaps additional tests for these should be added
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

        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(clientRepository, times(2)).saveClient(capture(capturedClients))

        val savedClients = capturedClients.allValues

        Assertions.assertEquals(2, savedClients.size)

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


        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(blSiteRepository, times(3)).save(capture(capturedBlacklistedSites))

        val savedSites = capturedBlacklistedSites.allValues

        Assertions.assertEquals(3, savedSites.size)

        Assertions.assertEquals(site1.uri, savedSites[0].uri)
        Assertions.assertEquals(site2.uri, savedSites[1].uri)
        Assertions.assertEquals(site3.uri, savedSites[2].uri)
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

        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long?, WhitelistedSite> = HashMap()
        whenever<WhitelistedSite>(wlSiteRepository.save(isA<WhitelistedSite>()))
            .thenAnswer(object : Answer<WhitelistedSite> {
                var id: Long = 345L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): WhitelistedSite {
                    val _site = invocation.arguments[0] as WhitelistedSite
                    if (_site.id == null) {
                        _site.id = id++
                    }
                    fakeDb[_site.id] = _site
                    return _site
                }
            })

        // unused by mockito (causs unnecessary stubbing exception
        /*
		when(wlSiteRepository.getById(anyLong())).thenAnswer(new Answer<WhitelistedSite>() {
			@Override
			public WhitelistedSite answer(InvocationOnMock invocation) throws Throwable {
				Long _id = (Long) invocation.getArguments()[0];
				return fakeDb.get(_id);
			}
		});
*/
        dataService.importData(reader)
        verify(wlSiteRepository, times(3)).save(capture(capturedWhitelistedSites))

        val savedSites = capturedWhitelistedSites.allValues

        Assertions.assertEquals(3, savedSites.size)

        Assertions.assertEquals(site1.clientId, savedSites[0].clientId)
        Assertions.assertEquals(site2.clientId, savedSites[1].clientId)
        Assertions.assertEquals(site3.clientId, savedSites[2].clientId)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportGrants() {
        val creationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)
        val accessDate1 = formatter.parse("2014-09-10T23:49:44.090+00:00", Locale.ENGLISH)

        val mockToken1 = mock<OAuth2AccessTokenEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockToken1.getId()).thenReturn(1L);
        val site1 = ApprovedSite()
        site1.id = 1L
        site1.clientId = "foo"
        site1.creationDate = creationDate1
        site1.accessDate = accessDate1
        site1.userId = "user1"
        site1.allowedScopes = setOf("openid", "phone")

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockToken1.getApprovedSite()).thenReturn(site1);
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

        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long, ApprovedSite> = HashMap()
        whenever(approvedSiteRepository.save(isA<ApprovedSite>()))
            .thenAnswer(object : Answer<ApprovedSite> {
                var id: Long = 343L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): ApprovedSite {
                    val _site = invocation.arguments[0] as ApprovedSite
                    val id = _site.id ?: (id++).also { _site.id = it }
                    fakeDb[id] = _site
                    return _site
                }
            })
        whenever(approvedSiteRepository.getById(isA())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeDb[_id]
        }
        // unused by mockito (causs unnecessary stubbing exception
        /*
		when(wlSiteRepository.getById(isNull(Long.class))).thenAnswer(new Answer<WhitelistedSite>() {
			Long id = 244L;
			@Override
			public WhitelistedSite answer(InvocationOnMock invocation) throws Throwable {
				WhitelistedSite _site = mock(WhitelistedSite.class);
				when(_site.getId()).thenReturn(id++);
				return _site;
			}
		});
*/
        whenever(tokenRepository.getAccessTokenById(eq((401L).toJavaId())))
            .thenAnswer(object : Answer<OAuth2AccessTokenEntity> {
                var id: Long = 221L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2AccessTokenEntity {
                    val _token = mock<OAuth2AccessTokenEntity>()
                    // unused by mockito (causs unnecessary stubbing exception
//				when(_token.getId()).thenReturn(id++);
                    return _token
                }
            })
        // unused by mockito (causs unnecessary stubbing exception
//		when(tokenRepository.getAccessTokensForApprovedSite(site1)).thenReturn(Lists.newArrayList(mockToken1));
        maps.accessTokenOldToNewIdMap[1L] = 401L
        dataService.importData(reader)
        //2 for sites, 1 for updating access token ref on #1
        verify(approvedSiteRepository, times(3)).save(capture(capturedApprovedSites))

        val savedSites: List<ApprovedSite> = fakeDb.values.toList()

        Assertions.assertEquals(2, savedSites.size)

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
                "{\"id\":1,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]" +
                "}")

        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        val fakeDb: MutableMap<Long?, AuthenticationHolderEntity> = HashMap()
        whenever<AuthenticationHolderEntity>(authHolderRepository.save(isA<AuthenticationHolderEntity>()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 356L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _holder = invocation.arguments[0] as AuthenticationHolderEntity
                    if (_holder.id == null) {
                        _holder.id = id++
                    }
                    fakeDb[_holder.id] = _holder
                    return _holder
                }
            })

        dataService.importData(reader)
        verify(authHolderRepository, times(2)).save(capture(capturedAuthHolders))

        val savedAuthHolders = capturedAuthHolders.allValues

        Assertions.assertEquals(2, savedAuthHolders.size)
        Assertions.assertEquals(holder1.authentication.oAuth2Request.clientId, savedAuthHolders[0].authentication.oAuth2Request.clientId)
        Assertions.assertEquals(holder2.authentication.oAuth2Request.clientId, savedAuthHolders[1].authentication.oAuth2Request.clientId)
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
                "{\"id\":1,\"description\":\"Scope 1\",\"icon\":\"glass\",\"value\":\"scope1\",\"allowDynReg\":false,\"defaultScope\":false}," +
                "{\"id\":2,\"description\":\"Scope 2\",\"icon\":\"ball\",\"value\":\"scope2\",\"allowDynReg\":true,\"defaultScope\":false}," +
                "{\"id\":3,\"description\":\"Scope 3\",\"icon\":\"road\",\"value\":\"scope3\",\"allowDynReg\":true,\"defaultScope\":true}" +
                "  ]" +
                "}"

        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))

        dataService.importData(reader)
        verify(sysScopeRepository, times(3)).save(capture(capturedScope))

        val savedScopes = capturedScope.allValues

        Assertions.assertEquals(3, savedScopes.size)
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

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedClient1.getClientId()).thenReturn("mocked_client_1");
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

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedClient2.getClientId()).thenReturn("mocked_client_2");
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
                "{\"id\":1,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]," +
                "\"" + MITREidDataService.REFRESHTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")
        System.err.println(configJson)

        val reader = JsonReader(StringReader(configJson))
        val fakeRefreshTokenTable: MutableMap<Long, OAuth2RefreshTokenEntity> = HashMap()
        val fakeAuthHolderTable: MutableMap<Long, AuthenticationHolderEntity> = HashMap()
        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2RefreshTokenEntity> {
                var id: Long = 343L
                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2RefreshTokenEntity {
                    val _token = invocation.arguments[0] as OAuth2RefreshTokenEntity
                    val id = _token.id ?: (id++).also { _token.id = it }
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
            // unused by mockito (causs unnecessary stubbing exception
//				when(_client.getClientId()).thenReturn(_clientId);
            _client
        }
        whenever<AuthenticationHolderEntity>(authHolderRepository.save(isA<AuthenticationHolderEntity>()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 356L
                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _holder = invocation.arguments[0] as AuthenticationHolderEntity
                    val id = _holder.id ?: (id++).also { _holder.id = it }
                    fakeAuthHolderTable[id] = _holder
                    return _holder
                }
            })
        whenever(authHolderRepository.getById(ArgumentMatchers.anyLong())).thenAnswer { invocation ->
            val _id = invocation.arguments[0] as Long
            fakeAuthHolderTable[_id]
        }
        dataService.importData(reader)

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> = fakeRefreshTokenTable.values.sortedWith(refreshTokenIdComparator())
            //capturedRefreshTokens.getAllValues();

        Assertions.assertEquals(356L, savedRefreshTokens[0].authenticationHolder.id)
        Assertions.assertEquals(357L, savedRefreshTokens[1].authenticationHolder.id)
    }

    @Test(expected = UnsupportedOperationException::class)
    @Throws(IOException::class)
    fun testExportDisabled() {
        val writer = JsonWriter(StringWriter())
        dataService.exportData(writer)
    }
}
