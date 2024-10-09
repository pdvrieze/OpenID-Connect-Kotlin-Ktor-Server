package org.mitre.openid.connect.service.impl.ktor

import com.nimbusds.jwt.JWTParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.platform.commons.util.ReflectionUtils
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
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
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Captor
import org.mockito.Mock
import org.mockito.invocation.InvocationOnMock
import org.mockito.kotlin.capture
import org.mockito.kotlin.eq
import org.mockito.kotlin.isA
import org.mockito.kotlin.mock
import org.mockito.kotlin.reset
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField
import java.util.*
import kotlin.reflect.KClass

abstract class TestMITREiDDataServiceBase<DS : MITREidDataService> {
    @Mock
    protected open lateinit var clientRepository: OAuth2ClientRepository

    @Mock
    protected lateinit var approvedSiteRepository: ApprovedSiteRepository

    @Mock
    protected lateinit var wlSiteRepository: WhitelistedSiteRepository

    @Mock
    protected lateinit var blSiteRepository: BlacklistedSiteRepository

    @Mock
    protected lateinit var authHolderRepository: AuthenticationHolderRepository

    @Mock
    protected lateinit var tokenRepository: OAuth2TokenRepository

    @Mock
    protected lateinit var sysScopeRepository: SystemScopeRepository

    protected val formatter: DateTimeFormatter = DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .append(DateTimeFormatter.ISO_LOCAL_DATE)
        .appendLiteral('T')
        .appendValue(ChronoField.HOUR_OF_DAY, 2)
        .appendLiteral(':')
        .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
        .optionalStart()
        .appendLiteral(':')
        .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
        .parseLenient()
        .optionalStart()
        .appendFraction(ChronoField.NANO_OF_SECOND, 3, 3, true)
        .optionalEnd()
        .appendOffsetId()
        .parseStrict()
        .toFormatter()
        .withZone(ZoneOffset.UTC)

    protected lateinit var maps: MITREidDataServiceMaps

    protected abstract var dataService: DS

    @Captor
    private lateinit var capturedRefreshTokens: ArgumentCaptor<OAuth2RefreshTokenEntity>

    @Captor
    private lateinit var capturedAccessTokens: ArgumentCaptor<OAuth2AccessTokenEntity>

    @Captor
    protected lateinit var capturedClients: ArgumentCaptor<ClientDetailsEntity>

    @Captor
    protected lateinit var capturedBlacklistedSites: ArgumentCaptor<BlacklistedSite>

    @Captor
    protected lateinit var capturedWhitelistedSites: ArgumentCaptor<WhitelistedSite>

    @Captor
    protected lateinit var capturedApprovedSites: ArgumentCaptor<ApprovedSite>

    @Captor
    protected lateinit var capturedAuthHolders: ArgumentCaptor<AuthenticationHolderEntity>

    @Captor
    protected lateinit var capturedScope: ArgumentCaptor<SystemScope>


    protected fun commonPrepare(mapsHolder: KClass<DS>) {
        reset(clientRepository, approvedSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, wlSiteRepository, blSiteRepository)

        maps = ReflectionUtils.tryToReadFieldValue(mapsHolder.java, "maps", dataService).get() as MITREidDataServiceMaps
    }

    protected fun testImportRefreshTokensBase() {
        val expirationDate1 = Instant.from(formatter.parse("2014-09-10T22:49:44.090+00:00"))

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
        //		when(mockedAuthHolder1.getId()).thenReturn(1L);
        val token1 = OAuth2RefreshTokenEntity()
        token1.id = 1L
        token1.client = mockedClient1
        token1.expirationInstant = expirationDate1
        token1.jwt =
            JWTParser.parse("eyJhbGciOiJub25lIn0.eyJqdGkiOiJmOTg4OWQyOS0xMTk1LTQ4ODEtODgwZC1lZjVlYzAwY2Y4NDIifQ.")
        token1.authenticationHolder = mockedAuthHolder1

        val expirationDate2 = Instant.from(formatter.parse("2015-01-07T18:31:50.079+00:00"))

        val mockedClient2 = mock<ClientDetailsEntity>()
        whenever(mockedClient2.clientId).thenReturn("mocked_client_2")

        val mockedAuthHolder2 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
        //		when(mockedAuthHolder2.getId()).thenReturn(2L);
        val token2 = OAuth2RefreshTokenEntity(
            id = 2L,
            client = mockedClient2,
            expirationInstant = expirationDate2,
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
        whenever(clientRepository.getClientByClientId(anyString())).thenAnswer { invocation ->
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

    protected fun testImportAccessTokensBase() {
        val expirationDate1 = Instant.from(formatter.parse("2014-09-10T22:49:44.090+00:00"))

        val mockedClient1 = mock<ClientDetailsEntity>()
        whenever(mockedClient1.clientId).thenReturn("mocked_client_1")

        val mockedAuthHolder1 = mock<AuthenticationHolderEntity>()

        // unused by mockito (causs unnecessary stubbing exception
        //		when(mockedAuthHolder1.getId()).thenReturn(1L);
        val token1 = OAuth2AccessTokenEntity(
            id = 1L,
            expirationInstant = expirationDate1,
            client = mockedClient1,
            scope = setOf("id-token"),
            jwt = JWTParser.parse("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0MTI3ODk5NjgsInN1YiI6IjkwMzQyLkFTREZKV0ZBIiwiYXRfaGFzaCI6InptTmt1QmNRSmNYQktNaVpFODZqY0EiLCJhdWQiOlsiY2xpZW50Il0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC9vcGVuaWQtY29ubmVjdC1zZXJ2ZXItd2ViYXBwXC8iLCJpYXQiOjE0MTI3ODkzNjh9.xkEJ9IMXpH7qybWXomfq9WOOlpGYnrvGPgey9UQ4GLzbQx7JC0XgJK83PmrmBZosvFPCmota7FzI_BtwoZLgAZfFiH6w3WIlxuogoH-TxmYbxEpTHoTsszZppkq9mNgOlArV4jrR9y3TPo4MovsH71dDhS_ck-CvAlJunHlqhs0"),
            authenticationHolder = mockedAuthHolder1,
            tokenType = "Bearer",
        )

        val expirationDate2 = Instant.from(formatter.parse("2015-01-07T18:31:50.079+00:00"))

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
            expirationInstant = expirationDate2,
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

        whenever(tokenRepository.getRefreshTokenById(eq(1L))).thenReturn(mockRefreshToken2)
        whenever(tokenRepository.getRefreshTokenById(eq(402L))).thenAnswer { invocation ->
            mock<OAuth2RefreshTokenEntity>()
        }


        maps.authHolderOldToNewIdMap[1L] = 401L
        maps.authHolderOldToNewIdMap[2L] = 403L
        maps.refreshTokenOldToNewIdMap[1L] = 402L

        dataService.importData(configJson)

        //2 times for token, 2 times to update client, 2 times to update authHolder, 1 times to update refresh token
        verify(tokenRepository, times(7)).saveAccessToken(capture(capturedAccessTokens))

        val savedAccessTokens: List<OAuth2AccessTokenEntity> = fakeDb.values.sortedWith(accessTokenIdComparator())

        assertEquals(2, savedAccessTokens.size)

        assertEquals(token1.client!!.clientId, savedAccessTokens[0].client!!.clientId)
        assertEquals(token1.expiration, savedAccessTokens[0].expiration)
        assertEquals(token1.value, savedAccessTokens[0].value)

        assertEquals(token2.client!!.clientId, savedAccessTokens[1].client!!.clientId)
        assertEquals(token2.expiration, savedAccessTokens[1].expiration)
        assertEquals(token2.value, savedAccessTokens[1].value)
    }

    fun instant(s:String) = Instant.from(formatter.parse(s))
    fun instant(s:String, locale: Locale) = instant(s)

    protected class refreshTokenIdComparator : Comparator<OAuth2RefreshTokenEntity> {
        override fun compare(entity1: OAuth2RefreshTokenEntity, entity2: OAuth2RefreshTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

    protected class accessTokenIdComparator : Comparator<OAuth2AccessTokenEntity> {
        override fun compare(entity1: OAuth2AccessTokenEntity, entity2: OAuth2AccessTokenEntity): Int {
            return entity1.id!!.compareTo(entity2.id!!)
        }
    }

}
