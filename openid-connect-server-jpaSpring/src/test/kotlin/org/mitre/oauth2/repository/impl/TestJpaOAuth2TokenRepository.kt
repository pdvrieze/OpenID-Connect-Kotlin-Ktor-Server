package org.mitre.oauth2.repository.impl

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.jpa.AuthenticationHolderEntity
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.junit.jupiter.MockitoExtension
import java.time.Instant
import javax.persistence.EntityManager

@ExtendWith(MockitoExtension::class)
class TestJpaOAuth2TokenRepository {

    @Mock
    private lateinit var entityManager: EntityManager

    @InjectMocks
    private lateinit var repository: JpaOAuth2TokenRepository

    @BeforeEach
    fun setUp() {
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
    @Disabled("JPA isn't configured")
    fun testGetAccessTokensByUserName() {
        val tokens = repository.getAccessTokensByUserName("user1")
        assertEquals(2, tokens.size.toLong())
        assertEquals("user1", tokens.iterator().next().authenticationHolder.userAuth!!.name)
    }

    @Test
    @Disabled("Doesn't work correctly")
    fun testGetRefreshTokensByUserName() {
        val tokens = repository.getRefreshTokensByUserName("user2")
        assertEquals(3, tokens.size.toLong())
        assertEquals("user2", tokens.iterator().next().authenticationHolder.userAuth!!.name)
    }

    @Test
    @Disabled("Doesn't work correctly")
    fun testGetAllAccessTokens() {
        val tokens = repository.allAccessTokens
        assertEquals(4, tokens.size.toLong())
    }

    @Test
    @Disabled("Doesn't work correctly")
    fun testGetAllRefreshTokens() {
        val tokens = repository.allRefreshTokens
        assertEquals(5, tokens.size.toLong())
    }

    private fun createAccessToken(name: String): OAuth2AccessTokenEntity {
        assert(entityManager != null)

        val userAuth = SavedUserAuthentication(
            name = name,
        ).let {
            entityManager.merge(it)
        }

        val authHolder = AuthenticationHolderEntity(requestTime = Instant.now()).let {
            it.userAuth = userAuth
            entityManager.merge(it)
        }

        val accessToken = OAuth2AccessTokenEntity(
            authenticationHolder = authHolder,
            expirationInstant = Instant.now().plusSeconds(120),
            jwt = PlainJWT(JWTClaimsSet.Builder().build())
        )
        entityManager.merge(accessToken)

        return accessToken
    }

    private fun createRefreshToken(name: String): OAuth2RefreshTokenEntity {
        val userAuth = SavedUserAuthentication(name = name).let {
            entityManager.merge(it)
        }

        val authHolder = AuthenticationHolderEntity(requestTime = Instant.now()).let {
            it.userAuth = userAuth
            entityManager.merge(it)
        }

        return OAuth2RefreshTokenEntity().let {
            it.authenticationHolder = authHolder
            entityManager.merge(it)
        }
    }
}
