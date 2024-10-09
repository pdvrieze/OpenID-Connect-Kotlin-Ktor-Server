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
package org.mitre.openid.connect.service.impl.ktor

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
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.service.MITREidDataService.Companion.ACCESSTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.AUTHENTICATIONHOLDERS
import org.mitre.openid.connect.service.MITREidDataService.Companion.BLACKLISTEDSITES
import org.mitre.openid.connect.service.MITREidDataService.Companion.CLIENTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.GRANTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.REFRESHTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.SYSTEMSCOPES
import org.mitre.openid.connect.service.MITREidDataService.Companion.WHITELISTEDSITES
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyLong
import org.mockito.Captor
import org.mockito.invocation.InvocationOnMock
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.junit.jupiter.MockitoSettings
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.quality.Strictness
import org.mockito.stubbing.Answer
import java.io.IOException
import java.text.ParseException
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
@MockitoSettings(strictness = Strictness.WARN)
class TestMITREidDataService_1_1 : TestMITREiDDataServiceBase<MITREidDataService_1_1>() {
    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    override lateinit var dataService: MITREidDataService_1_1

    @BeforeEach
    fun prepare() {
        dataService = MITREidDataService_1_1(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(MITREidDataService_1_1::class)
    }

    @Test
    override fun testImportRefreshTokens() {
        super.testImportRefreshTokens()
    }

    @Test
    override fun testImportAccessTokens() {
        super.testImportAccessTokens()
    }


    //several new client fields added in 1.1, perhaps additional tests for these should be added
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
        testImportAuthenticationHolders(true)
    }

    @Test
    fun testImportSystemScopes() {
        super.testImportSystemScopes(false)
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        val expiration1 = "2014-09-10T22:49:44.090+00:00"
        val expirationDate1 = Instant.from(formatter.parse(expiration1))

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
            expirationInstant = expirationDate1,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ."),
            authenticationHolder = holder1,
        )

        val expirationDate2 = Instant.from(formatter.parse("2015-01-07T18:31:50.079+00:00"))

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
            expirationInstant = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ."),
            authenticationHolder = holder2,
        )

        val configJson = ("{" +
                "\"$SYSTEMSCOPES\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$CLIENTS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [" +
                "{\"id\":1,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},"
                + "\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"clientAuthorization\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},"
                + "\"userAuthentication\":null}}" +
                "  ]," +
                "\"$REFRESHTOKENS\": [" +
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
