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
import kotlinx.serialization.json.JsonArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.service.MITREidDataService.Companion.ACCESSTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.AUTHENTICATIONHOLDERS
import org.mitre.openid.connect.service.MITREidDataService.Companion.BLACKLISTEDSITES
import org.mitre.openid.connect.service.MITREidDataService.Companion.CLIENTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.GRANTS
import org.mitre.openid.connect.service.MITREidDataService.Companion.REFRESHTOKENS
import org.mitre.openid.connect.service.MITREidDataService.Companion.SYSTEMSCOPES
import org.mitre.openid.connect.service.MITREidDataService.Companion.WHITELISTEDSITES
import org.mitre.util.asString
import org.mitre.util.getLogger
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyLong
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
class TestMITREidDataService_1_2 : TestMITREiDDataServiceBase<MITREidDataService_1_2>() {

    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    override lateinit var dataService: MITREidDataService_1_2

    @BeforeEach
    fun prepare() {
        dataService = MITREidDataService_1_2(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository)
        commonPrepare(MITREidDataService_1_2::class)
    }

    private inner class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
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
    @Throws(IOException::class, ParseException::class)
    fun testFixRefreshTokenAuthHolderReferencesOnImport() {
        val expirationDate1 = instant("2014-09-10T22:49:44.090+00:00")

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

        val expirationDate2 = instant("2015-01-07T18:31:50.079+00:00")

        val mockedClient2 = mock<ClientDetailsEntity>()

        // unused by mockito (causs unnecessary stubbing exception
//		when(mockedClient2.getClientId()).thenReturn("mocked_client_2");
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

        val token2 = OAuth2RefreshTokenEntity(
            id = 2L,
            client = mockedClient2,
            expirationInstant = expirationDate2,
            jwt = JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ."),
            authenticationHolder = holder2,
        )

        val configJson = ("{\"$SYSTEMSCOPES\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$CLIENTS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [" +
                "{\"id\":1,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client1\",\"redirectUri\":\"http://foo.com\"},\"userAuthentication\":null}}," +
                "{\"id\":2,\"authentication\":{\"authorizationRequest\":{\"clientId\":\"client2\",\"redirectUri\":\"http://bar.com\"},\"userAuthentication\":null}}  " +
                "]," +
                "\"$REFRESHTOKENS\": [" +
                "{\"id\":1,\"clientId\":\"mocked_client_1\",\"expiration\":\"2014-09-10T22:49:44.090+00:00\",\"authenticationHolderId\":1,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.\"}," +
                "{\"id\":2,\"clientId\":\"mocked_client_2\",\"expiration\":\"2015-01-07T18:31:50.079+00:00\",\"authenticationHolderId\":2,\"value\":\"eyJhbGciOiJub25lIn0.eyJqdGkiOiJlYmEyYjc3My0xNjAzLTRmNDAtOWQ3MS1hMGIxZDg1OWE2MDAifQ.\"}  " +
                "]}")
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
                    val id = _holder.id ?: id++.also { _holder.id = it }
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

    private fun jsonArrayToStringSet(a: JsonArray): Set<String> {
        val s: MutableSet<String> = HashSet()
        for (jsonElement in a) {
            s.add(jsonElement.asString())
        }
        return s
    }

    companion object {
        private val logger = getLogger<TestMITREidDataService_1_2>()
    }
}
