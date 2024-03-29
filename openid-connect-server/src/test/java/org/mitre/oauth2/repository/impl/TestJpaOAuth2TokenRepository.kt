package org.mitre.oauth2.repository.impl

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

@ContextConfiguration(classes = [TestDatabaseConfiguration::class])
@Transactional
@ExtendWith(SpringExtension::class)
class TestJpaOAuth2TokenRepository {
    @Autowired
    private lateinit var repository: JpaOAuth2TokenRepository

    @PersistenceContext
    private lateinit var entityManager: EntityManager

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
    fun testGetAccessTokensByUserName() {
        val tokens = repository.getAccessTokensByUserName("user1")
        assertEquals(2, tokens.size.toLong())
        assertEquals("user1", tokens.iterator().next().authenticationHolder.userAuth!!.name)
    }

    @Test
    fun testGetRefreshTokensByUserName() {
        val tokens = repository.getRefreshTokensByUserName("user2")
        assertEquals(3, tokens.size.toLong())
        assertEquals("user2", tokens.iterator().next().authenticationHolder.userAuth!!.name)
    }

    @Test
    fun testGetAllAccessTokens() {
        val tokens = repository.allAccessTokens
        assertEquals(4, tokens.size.toLong())
    }

    @Test
    fun testGetAllRefreshTokens() {
        val tokens = repository.allRefreshTokens
        assertEquals(5, tokens.size.toLong())
    }

    private fun createAccessToken(name: String): OAuth2AccessTokenEntity {
        var userAuth = SavedUserAuthentication()
        userAuth.setName(name)
        userAuth = entityManager.merge(userAuth)

        var authHolder = AuthenticationHolderEntity()
        authHolder.userAuth = userAuth
        authHolder = entityManager.merge(authHolder)

        var accessToken = OAuth2AccessTokenEntity()
        accessToken.authenticationHolder = authHolder

        accessToken = entityManager.merge(accessToken)

        return accessToken
    }

    private fun createRefreshToken(name: String): OAuth2RefreshTokenEntity {
        var userAuth = SavedUserAuthentication()
        userAuth.setName(name)
        userAuth = entityManager.merge(userAuth)

        var authHolder = AuthenticationHolderEntity()
        authHolder.userAuth = userAuth
        authHolder = entityManager.merge(authHolder)

        var refreshToken = OAuth2RefreshTokenEntity()
        refreshToken.authenticationHolder = authHolder

        refreshToken = entityManager.merge(refreshToken)

        return refreshToken
    }
}
