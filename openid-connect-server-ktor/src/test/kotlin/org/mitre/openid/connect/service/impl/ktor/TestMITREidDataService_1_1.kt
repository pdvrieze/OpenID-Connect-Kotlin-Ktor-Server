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
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
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
import org.mockito.kotlin.capture
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.IOException
import java.text.ParseException
import java.time.Instant
import java.util.*

@ExtendWith(MockitoExtension::class)
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

    private inner class accessTokenIdComparator : Comparator<OAuth2AccessTokenEntity> {
        override fun compare(entity1: OAuth2AccessTokenEntity, entity2: OAuth2AccessTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

    @Test
    @Throws(IOException::class, ParseException::class)
    override fun testImportAccessTokens() {
        super.testImportAccessTokens()
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
        val creationDate1 = Instant.from(formatter.parse("2014-09-10T22:49:44.090+00:00"))
        val accessDate1 = Instant.from(formatter.parse("2014-09-10T23:49:44.090+00:00"))

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
        val creationDate2 = Instant.from(formatter.parse("2014-09-11T18:49:44.090+00:00"))
        val accessDate2 = Instant.from(formatter.parse("2014-09-11T20:49:44.090+00:00"))
        val timeoutDate2 = Instant.from(formatter.parse("2014-10-01T20:49:44.090+00:00"))

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
        // unused by mockito (causs unnecessary stubbing exception
        /*
		when(wlSiteRepository.getById(isNull(Long.class))).thenAnswer(new Answer<WhitelistedSite>() {
			Long id = 432L;
			@Override
			public WhitelistedSite answer(InvocationOnMock invocation) throws Throwable {
				WhitelistedSite _site = mock(WhitelistedSite.class);
				when(_site.getId()).thenReturn(id++);
				return _site;
			}
		}) */

        whenever(tokenRepository.getAccessTokenById(anyLong()))
            .thenAnswer(object : Answer<OAuth2AccessTokenEntity> {
                var id: Long = 245L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): OAuth2AccessTokenEntity {
                    assertEquals(245L, invocation.arguments[0])
                    val _token = mock<OAuth2AccessTokenEntity>()
                    // unused by mockito (causs unnecessary stubbing exception
//				when(_token.getId()).thenReturn(id++);
                    return _token
                }
            })

        maps.accessTokenOldToNewIdMap[1L] = 245L

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
            isApproved = true,
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

        val fakeDb: MutableMap<Long, AuthenticationHolderEntity> = HashMap()
        whenever(authHolderRepository.save(isA<AuthenticationHolderEntity>()))
            .thenAnswer(object : Answer<AuthenticationHolderEntity> {
                var id: Long = 243L

                @Throws(Throwable::class)
                override fun answer(invocation: InvocationOnMock): AuthenticationHolderEntity {
                    val _site = invocation.arguments[0] as AuthenticationHolderEntity
                    val id = _site.id ?: (id++).also { _site.id = it }
                    fakeDb[id] = _site
                    return _site
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

        val configJson = "{" +
                "\"$CLIENTS\": [], " +
                "\"$ACCESSTOKENS\": [], " +
                "\"$REFRESHTOKENS\": [], " +
                "\"$GRANTS\": [], " +
                "\"$WHITELISTEDSITES\": [], " +
                "\"$BLACKLISTEDSITES\": [], " +
                "\"$AUTHENTICATIONHOLDERS\": [], " +
                "\"$SYSTEMSCOPES\": [" +
                "{\"id\":1,\"description\":\"Scope 1\",\"icon\":\"glass\",\"value\":\"scope1\",\"allowDynReg\":false,\"defaultScope\":false}," +
                "{\"id\":2,\"description\":\"Scope 2\",\"icon\":\"ball\",\"value\":\"scope2\",\"allowDynReg\":true,\"defaultScope\":false}," +
                "{\"id\":3,\"description\":\"Scope 3\",\"icon\":\"road\",\"value\":\"scope3\",\"allowDynReg\":true,\"defaultScope\":true}" +
                "  ]" +
                "}"

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
