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
package org.mitre.openid.connect.service.impl.spring

import com.nimbusds.jwt.JWTParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
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
import org.mitre.openid.connect.service.MITREidDataService.Companion.ACCESSTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.AUTHENTICATIONHOLDERS
import org.mitre.openid.connect.service.MITREidDataService.Companion.BLACKLISTEDSITES
import org.mitre.openid.connect.service.MITREidDataService.Companion.CLIENTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.GRANTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.REFRESHTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.SYSTEMSCOPES
import org.mitre.openid.connect.service.MITREidDataService.Companion.WHITELISTEDSITES
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.Captor
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.jupiter.MockitoExtension
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
import org.springframework.util.ReflectionUtils
import java.io.IOException
import java.text.ParseException
import java.util.*

@ExtendWith(MockitoExtension::class)
class TestSpringidDataService_1_0 {
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

    @BeforeEach
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
        val token2 = OAuth2RefreshTokenEntity(
            id = 2L,
            client = mockedClient2,
            expiration = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ."),
            authenticationHolder = mockedAuthHolder2,
        )

        val configJson = ("{" +
                "\"$SYSTEMSCOPES\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$CLIENTS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [], " +
                "\"$REFRESHTOKENS\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")

        System.err.println(configJson)

        val fakeDb: MutableMap<Long, OAuth2RefreshTokenEntity> = HashMap()
        whenever(tokenRepository.saveRefreshToken(isA<OAuth2RefreshTokenEntity>()))
            .thenAnswer(object : Answer<OAuth2RefreshTokenEntity> {
                var id: Long = 343L

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
        whenever(authHolderRepository.getById(anyLong()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 678L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    return mock<AuthenticationHolderEntity>()
                }
            })

        maps.authHolderOldToNewIdMap[1L] = 678L
        maps.authHolderOldToNewIdMap[2L] = 679L
        dataService.importData(configJson)

        //2 times for token, 2 times to update client, 2 times to update authHolder
        verify(tokenRepository, times(6)).saveRefreshToken(capture(capturedRefreshTokens))

        val savedRefreshTokens: List<OAuth2RefreshTokenEntity> = fakeDb.values.sortedWith(refreshTokenIdComparator())
        //capturedRefreshTokens.getAllValues();

        assertEquals(2, savedRefreshTokens.size)

        assertEquals(token1.client!!.clientId, savedRefreshTokens[0].client!!.clientId)
        assertEquals(token1.expiration, savedRefreshTokens[0].expiration)
        assertEquals(token1.value, savedRefreshTokens[0].value)

        assertEquals(token2.client!!.clientId, savedRefreshTokens[1].client!!.clientId)
        assertEquals(token2.expiration, savedRefreshTokens[1].expiration)
        assertEquals(token2.value, savedRefreshTokens[1].value)
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
        val token1 = OAuth2AccessTokenEntity(
            id = 1L,
            expiration = expirationDate1,
            client = mockedClient1,
            scope = setOf("id-token"),
            jwt = JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0"),
            authenticationHolder = mockedAuthHolder1,
            tokenType = "Bearer",
        )

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
        val token2 = OAuth2AccessTokenEntity(
            id = 2L,
            client = mockedClient2,
            expiration = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ"),
            authenticationHolder = mockedAuthHolder2,
            refreshToken = mockRefreshToken2,
            scope = setOf("openid", "offline_access", "email", "profile"),
            tokenType = "Bearer",
        )

        val configJson = ("{" +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + CLIENTS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"refreshTokenId\":null,\"idTokenId\":null,\"scope\":[\"id-token\"],\"type\":\"Bearer\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"refreshTokenId\":1,\"idTokenId\":1,\"scope\":[\"openid\",\"offline_access\",\"email\",\"profile\"],\"type\":\"Bearer\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3OTI5NjgsImF1ZCI6WyJjbGllbnQiXSwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL29wZW5pZC1jb25uZWN0LXNlcnZlci13ZWJhcHBcLyIsImp0aSI6IjBmZGE5ZmRiLTYyYzItNGIzZS05OTdiLWU0M2VhMDUwMzNiOSIsImlhdCI6MTQxMjc4OTM2OH0.xgaVpRLYE5MzbgXfE0tZt823tjAm6Oh3_kdR1P2I9jRLR6gnTlBQFlYi3Y_0pWNnZSerbAE8Tn6SJHZ9k-curVG0-ByKichV7CNvgsE5X_2wpEaUzejvKf8eZ-BammRY-ie6yxSkAarcUGMvGGOLbkFcz5CtrBpZhfd75J49BIQ\"}" +
                "  ]" +
                "}")


        System.err.println(configJson)

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
        whenever(authHolderRepository.getById(anyLong()))
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
        maps.authHolderOldToNewIdMap[2L] = 403L
        maps.refreshTokenOldToNewIdMap[1L] = 402L

        dataService.importData(configJson)

        //2 times for token, 2 times to update client, 2 times to update authHolder, 1 times to update refresh token
        verify(tokenRepository, times(7)).saveAccessToken(capture(capturedAccessTokens))

        val savedAccessTokens: List<OAuth2AccessTokenEntity> = fakeDb.values.sortedWith(accessTokenIdComparator())

        assertEquals(2, savedAccessTokens.size)

        assertEquals(token1.client!!.clientId, savedAccessTokens[0].client!!.clientId)
        assertEquals(token1.expirationInstant, savedAccessTokens[0].expirationInstant)
        assertEquals(token1.value, savedAccessTokens[0].value)

        assertEquals(token2.client!!.clientId, savedAccessTokens[1].client!!.clientId)
        assertEquals(token2.expirationInstant, savedAccessTokens[1].expirationInstant)
        assertEquals(token2.value, savedAccessTokens[1].value)
    }


    //several new client fields added in 1.1, perhaps additional tests for these should be added
    @Test
    @Throws(IOException::class)
    fun testImportClients() {
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
        )

        val configJson = ("{" +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + CLIENTS + "\": [" +
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

        dataService.importData(configJson)

        verify(clientRepository, times(2)).saveClient(capture(capturedClients))

        val savedClients = capturedClients.allValues

        assertEquals(2, savedClients.size)

        assertEquals(client1.accessTokenValiditySeconds, savedClients[0].accessTokenValiditySeconds)
        assertEquals(client1.clientId, savedClients[0].clientId)
        assertEquals(client1.clientSecret, savedClients[0].clientSecret)
        assertEquals(client1.redirectUris, savedClients[0].redirectUris)
        assertEquals(client1.scope, savedClients[0].scope)
        assertEquals(client1.authorizedGrantTypes, savedClients[0].authorizedGrantTypes)
        assertEquals(client1.isAllowIntrospection, savedClients[0].isAllowIntrospection)

        assertEquals(client2.accessTokenValiditySeconds, savedClients[1].accessTokenValiditySeconds)
        assertEquals(client2.clientId, savedClients[1].clientId)
        assertEquals(client2.clientSecret, savedClients[1].clientSecret)
        assertEquals(client2.redirectUris, savedClients[1].redirectUris)
        assertEquals(client2.scope, savedClients[1].scope)
        assertEquals(client2.authorizedGrantTypes, savedClients[1].authorizedGrantTypes)
        assertEquals(client2.isAllowIntrospection, savedClients[1].isAllowIntrospection)
    }

    @Test
    @Throws(IOException::class)
    fun testImportBlacklistedSites() {
        val site1 = BlacklistedSite(id = 1L, uri = "http://foo.com")

        val site2 = BlacklistedSite(id = 2L, uri = "http://bar.com")

        val site3 = BlacklistedSite(id = 3L, uri = "http://baz.com")

        val configJson = "{" +
                "\"" + CLIENTS + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [" +
                "{\"id\":1,\"uri\":\"http://foo.com\"}," +
                "{\"id\":2,\"uri\":\"http://bar.com\"}," +
                "{\"id\":3,\"uri\":\"http://baz.com\"}" +
                "  ]" +
                "}"


        System.err.println(configJson)

        dataService.importData(configJson)

        verify(blSiteRepository, times(3)).save(capture(capturedBlacklistedSites))

        val savedSites = capturedBlacklistedSites.allValues

        assertEquals(3, savedSites.size)

        assertEquals(site1.uri, savedSites[0].uri)
        assertEquals(site2.uri, savedSites[1].uri)
        assertEquals(site3.uri, savedSites[2].uri)
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
                "\"" + CLIENTS + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [" +
                "{\"id\":1,\"clientId\":\"foo\"}," +
                "{\"id\":2,\"clientId\":\"bar\"}," +
                "{\"id\":3,\"clientId\":\"baz\"}" +
                "  ]" +
                "}"

        System.err.println(configJson)

        val fakeDb: MutableMap<Long?, WhitelistedSite> = HashMap()
        whenever(wlSiteRepository.save(isA<WhitelistedSite>()))
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

        dataService.importData(configJson)

        verify(wlSiteRepository, times(3)).save(capture(capturedWhitelistedSites))

        val savedSites = capturedWhitelistedSites.allValues

        assertEquals(3, savedSites.size)

        assertEquals(site1.clientId, savedSites[0].clientId)
        assertEquals(site2.clientId, savedSites[1].clientId)
        assertEquals(site3.clientId, savedSites[2].clientId)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testImportGrants() {
        val creationDate1 = formatter.parse("2014-09-10T22:49:44.090+00:00", Locale.ENGLISH)
        val accessDate1 = formatter.parse("2014-09-10T23:49:44.090+00:00", Locale.ENGLISH)

        val mockToken1 = mock<OAuth2AccessTokenEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockToken1.getId()).thenReturn(1L);
        val site1 = ApprovedSite(
            id = 1L,
            clientId = "foo",
            creationDate = creationDate1,
            accessDate = accessDate1,
            userId = "user1",
            allowedScopes = setOf("openid", "phone"),
        )

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockToken1.getApprovedSite()).thenReturn(site1);
        val creationDate2 = formatter.parse("2014-09-11T18:49:44.090+00:00", Locale.ENGLISH)
        val accessDate2 = formatter.parse("2014-09-11T20:49:44.090+00:00", Locale.ENGLISH)
        val timeoutDate2 = formatter.parse("2014-10-01T20:49:44.090+00:00", Locale.ENGLISH)

        val site2 = ApprovedSite(
            id = 2L,
            clientId = "bar",
            creationDate = creationDate2,
            accessDate = accessDate2,
            userId = "user2",
            allowedScopes = setOf("openid", "offline_access", "email", "profile"),
            timeoutDate = timeoutDate2,
        )

        val configJson = ("{" +
                "\"" + CLIENTS + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [], " +
                "\"" + GRANTS + "\": [" +
                "{\"id\":1,\"clientId\":\"foo\",\"creationDate\":\"2014-09-10T22:49:44.090+00:00\",\"accessDate\":\"2014-09-10T23:49:44.090+00:00\","
                + "\"userId\":\"user1\",\"whitelistedSiteId\":null,\"allowedScopes\":[\"openid\",\"phone\"], \"whitelistedSiteId\":1,"
                + "\"approvedAccessTokens\":[1]}," +
                "{\"id\":2,\"clientId\":\"bar\",\"creationDate\":\"2014-09-11T18:49:44.090+00:00\",\"accessDate\":\"2014-09-11T20:49:44.090+00:00\","
                + "\"timeoutDate\":\"2014-10-01T20:49:44.090+00:00\",\"userId\":\"user2\","
                + "\"allowedScopes\":[\"openid\",\"offline_access\",\"email\",\"profile\"]}" +
                "  ]" +
                "}")

        System.err.println(configJson)

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
        whenever(tokenRepository.getAccessTokenById(eq((401L))))
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
//		when(tokenRepository.getAccessTokensForApprovedSite(site1)).thenReturn(listOf(mockToken1));
        maps.accessTokenOldToNewIdMap[1L] = 401L

        dataService.importData(configJson)

        //2 for sites, 1 for updating access token ref on #1
        verify(approvedSiteRepository, times(3)).save(capture(capturedApprovedSites))

        val savedSites: List<ApprovedSite> = fakeDb.values.toList()

        assertEquals(2, savedSites.size)

        assertEquals(site1.clientId, savedSites[0].clientId)
        assertEquals(site1.accessDate, savedSites[0].accessDate)
        assertEquals(site1.creationDate, savedSites[0].creationDate)
        assertEquals(site1.allowedScopes, savedSites[0].allowedScopes)
        assertEquals(site1.timeoutDate, savedSites[0].timeoutDate)

        assertEquals(site2.clientId, savedSites[1].clientId)
        assertEquals(site2.accessDate, savedSites[1].accessDate)
        assertEquals(site2.creationDate, savedSites[1].creationDate)
        assertEquals(site2.allowedScopes, savedSites[1].allowedScopes)
        assertEquals(site2.timeoutDate, savedSites[1].timeoutDate)
    }

    @Test
    @Throws(IOException::class)
    fun testImportAuthenticationHolders() {
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

        val req2 = OAuth2Request(
            clientId = "client2",
            isApproved =  true,
            redirectUri = "http://bar.com",
        )
        val mockAuth2 = SavedUserAuthentication(name = "mockAuth2")
        val auth2 = OAuth2RequestAuthentication(req2, mockAuth2)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val configJson = ("{" +
                "\"" + CLIENTS + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + REFRESHTOKENS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [" +
                "{\"id\":1,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]" +
                "}")

        System.err.println(configJson)

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

        dataService.importData(configJson)

        verify(authHolderRepository, times(2)).save(capture(capturedAuthHolders))

        val savedAuthHolders = capturedAuthHolders.allValues

        assertEquals(2, savedAuthHolders.size)
        assertEquals(holder1.authentication.oAuth2Request.clientId, savedAuthHolders[0].authentication.oAuth2Request.clientId)
        assertEquals(holder2.authentication.oAuth2Request.clientId, savedAuthHolders[1].authentication.oAuth2Request.clientId)
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

        val configJson =
            """{"$CLIENTS": [], 
                |  "$ACCESSTOKENS": [],
                |  "$REFRESHTOKENS": [],
                |  "$GRANTS": [],
                |  "$WHITELISTEDSITES": [],
                |  "$BLACKLISTEDSITES": [],
                |  "$AUTHENTICATIONHOLDERS": [],
                |  "$SYSTEMSCOPES": [
                |    {
                |      "id":1,
                |      "description":"Scope 1",
                |      "icon":"glass",
                |      "value":"scope1",
                |      "allowDynReg":false,
                |      "defaultScope":false
                |    },{
                |      "id":2,
                |      "description":"Scope 2",
                |      "icon":"ball",
                |      "value":"scope2",
                |      "allowDynReg":true,
                |      "defaultScope":false
                |    },{
                |      "id":3,
                |      "description":"Scope 3",
                |      "icon":"road",
                |      "value":"scope3",
                |      "allowDynReg":true,
                |      "defaultScope":true
                |    }
                |  ]
                |}""".trimMargin()

        System.err.println(configJson)

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
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = formatter.parse(expiration1, Locale.ENGLISH)

        val mockedClient1 = mock<ClientDetailsEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedClient1.getClientId()).thenReturn("mocked_client_1");
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

        val token1 = OAuth2RefreshTokenEntity(
            id = 1L,
            client = mockedClient1,
            expiration = expirationDate1,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ."),
            authenticationHolder = holder1,
        )

        val expiration2 = "2015-01-07T18:31:50.079+00:00"
        val expirationDate2 = formatter.parse(expiration2, Locale.ENGLISH)

        val mockedClient2 = mock<ClientDetailsEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedClient2.getClientId()).thenReturn("mocked_client_2");
        val req2 = OAuth2Request(
            clientId = "client2",
            isApproved = true,
            redirectUri = "http://bar.com",
        )

        val mockAuth2 = SavedUserAuthentication(name ="mockAuth2")
        val auth2 = OAuth2RequestAuthentication(req2, mockAuth2)

        val holder2 = AuthenticationHolderEntity()
        holder2.id = 2L
        holder2.authentication = auth2

        val token2 = OAuth2RefreshTokenEntity(
            id = 2L,
            client = mockedClient2,
            expiration = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ."),
            authenticationHolder = holder2,
        )

        val configJson = ("{" +
                "\"" + SYSTEMSCOPES + "\": [], " +
                "\"" + ACCESSTOKENS + "\": [], " +
                "\"" + CLIENTS + "\": [], " +
                "\"" + GRANTS + "\": [], " +
                "\"" + WHITELISTEDSITES + "\": [], " +
                "\"" + BLACKLISTEDSITES + "\": [], " +
                "\"" + AUTHENTICATIONHOLDERS + "\": [" +
                "{\"id\":1,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]," +
                "\"" + REFRESHTOKENS + "\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\","
                + "\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\","
                + "\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}" +
                "  ]" +
                "}")
        System.err.println(configJson)

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
        whenever(authHolderRepository.getById(anyLong())).thenAnswer { invocation ->
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

    @Test
    fun testExportDisabled() {
        assertThrows<UnsupportedOperationException> {
            dataService.exportData()
        }
    }
}
