package io.github.pdvrieze.auth.repository.exposed

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import io.github.pdvrieze.auth.SavedAuthentication
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mitre.oauth2.model.KtorAuthenticationHolder
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import java.time.Instant

class TestExposedOAuth2TokenRepository {
    private val dbName = "TestMemDB"

    private var database: Database = Database.connect("jdbc:h2:mem:$dbName;DB_CLOSE_DELAY=-1;", driver = "org.h2.Driver", "root")

    private lateinit var authenticationHolderRepository: AuthenticationHolderRepository

    private lateinit var clientRepository: OAuth2ClientRepository

    private lateinit var repository: ExposedOauth2TokenRepository

    @BeforeEach
    fun setUp() {
        authenticationHolderRepository = ExposedAuthenticationHolderRepository(database)
        clientRepository = ExposedOauth2ClientRepository(database)
        repository = ExposedOauth2TokenRepository(database, authenticationHolderRepository, clientRepository)

        transaction(database) {
            for (table in listOf(RefreshTokens, AccessTokens, AuthenticationHolders, SavedUserAuths)) {
                table.deleteAll()
            }
        }

        createAccessToken("user1")
        createAccessToken("user1")
        createAccessToken("user2")
        createAccessToken("user2")

        createRefreshToken("user1")
        createRefreshToken("user1")
        createRefreshToken("user2")
        createRefreshToken("user2")
        createRefreshToken("user2")
    }

    @Test
    fun testGetAccessTokensByUserName() {
        val tokens = repository.getAccessTokensByUserName("user1")
        Assertions.assertEquals(2, tokens.size.toLong())
        Assertions.assertEquals("user1", tokens.iterator().next().authenticationHolder.subjectAuth!!.principalName)
    }

    @Test
    fun testGetRefreshTokensByUserName() {
        val tokens = repository.getRefreshTokensByUserName("user2")
        Assertions.assertEquals(3, tokens.size.toLong())
        Assertions.assertEquals("user2", tokens.iterator().next().authenticationHolder.subjectAuth!!.principalName)
    }

    @Test
    fun testGetAllAccessTokens() {
        val tokens = repository.allAccessTokens
        Assertions.assertEquals(4, tokens.size.toLong())
    }

    @Test
    fun testGetAllRefreshTokens() {
        val tokens = repository.allRefreshTokens
        Assertions.assertEquals(5, tokens.size.toLong())
    }

    private fun createAccessToken(name: String): OAuth2AccessTokenEntity {
        return transaction(database) {
            val requestTime = Instant.now()

            val userAuthId = SavedUserAuths.select(SavedUserAuths.id).where { SavedUserAuths.name eq name }.singleOrNull()?.get(SavedUserAuths.id)
                ?: SavedUserAuths.insertAndGetId { it[this.name] = name }
            val userAuth = SavedAuthentication(name, userAuthId.value, requestTime, emptyList(), emptySet())

            val authHolderId = AuthenticationHolders.insertAndGetId {
                it[clientId] = "fooClient"
                it[this.userAuthId] = userAuthId.value
                it[this.requestTime] = requestTime
            }
            val authHolder =
                KtorAuthenticationHolder(
                    authentication = userAuth,
                    authorizationRequest = PlainAuthorizationRequest(clientId = "anyClient", requestTime = requestTime),
                    id = authHolderId.value
                )

            val accessTokenId = AccessTokens.insertAndGetId {
                it[this.authHolderId] = authHolderId.value
                it[tokenValue] = nextTokenValue()
            }
            OAuth2AccessTokenEntity(
                id = accessTokenId.value,
                authenticationHolder = authHolder,
                expirationInstant = requestTime.plusSeconds(120),
                jwt = PlainJWT(JWTClaimsSet.Builder().build()),
            )
        }
    }

    private fun createRefreshToken(name: String): OAuth2RefreshTokenEntity {
        return transaction(database) {
            val requestTime = Instant.now()
            val userAuthId = SavedUserAuths.select(SavedUserAuths.id).where { SavedUserAuths.name eq name }.singleOrNull()?.get(SavedUserAuths.id)
                ?: SavedUserAuths.insertAndGetId { it[this.name] = name }
            val userAuth = SavedAuthentication(name, userAuthId.value, requestTime)

            val authHolderId = AuthenticationHolders.insertAndGetId {
                it[clientId] = "myClientId"
                it[this.userAuthId] = userAuthId.value
                it[this.requestTime] = requestTime
            }
            val authHolder = KtorAuthenticationHolder(
                authentication = userAuth,
                authorizationRequest = PlainAuthorizationRequest(clientId = "foo", requestTime = requestTime)
            )

            val refreshTokenId = RefreshTokens.insertAndGetId {
                it[this.authHolderId] = authHolderId.value
                it[tokenValue] = nextTokenValue()
            }
            OAuth2RefreshTokenEntity(id = refreshTokenId.value, authenticationHolder = authHolder)
        }
    }

    companion object {
        private var tokenValue = 1

        fun nextTokenValue(): String {
            val claimsSet = JWTClaimsSet.Builder()
                .jwtID((tokenValue++).toString().padStart(5, '0'))
                .build()
            val t = PlainJWT(claimsSet)
            return t.serialize()

        }
    }
}
