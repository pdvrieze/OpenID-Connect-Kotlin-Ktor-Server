package org.mitre.oauth2.repository

import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.resolver.OAuth2TokenResolver
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.uma.model.ResourceSet

interface OAuth2TokenRepository : OAuth2TokenResolver {
    fun saveAccessToken(token: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity

    fun getRefreshTokenByValue(refreshTokenValue: String): OAuth2RefreshTokenEntity?

    override fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity?

    fun clearAccessTokensForRefreshToken(refreshToken: OAuth2RefreshTokenEntity)

    fun removeRefreshToken(refreshToken: OAuth2RefreshTokenEntity)

    fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity

    fun getAccessTokenByValue(accessTokenValue: String): OAuth2AccessTokenEntity?

    override fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity?

    fun removeAccessToken(accessToken: OAuth2AccessTokenEntity)

    fun clearTokensForClient(client: OAuthClientDetails)

    fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity>

    fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity>

    fun getAccessTokensByUserName(name: String): Set<OAuth2AccessTokenEntity>

    fun getRefreshTokensByUserName(name: String): Set<OAuth2RefreshTokenEntity>

    val allAccessTokens: Set<OAuth2AccessTokenEntity>

    val allRefreshTokens: Set<OAuth2RefreshTokenEntity>

    val allExpiredAccessTokens: Set<OAuth2AccessTokenEntity>

    fun getAllExpiredAccessTokens(pageCriteria: PageCriteria): Set<OAuth2AccessTokenEntity>

    val allExpiredRefreshTokens: Set<OAuth2RefreshTokenEntity>

    fun getAllExpiredRefreshTokens(pageCriteria: PageCriteria): Set<OAuth2RefreshTokenEntity>

    fun getAccessTokensForResourceSet(rs: ResourceSet): Set<OAuth2AccessTokenEntity>

    /**
     * removes duplicate access tokens.
     *
     */
    @Deprecated(
        """this method was added to return the remove duplicate access tokens values
	  so that {code removeAccessToken(OAuth2AccessTokenEntity o)} would not to fail. the
	  removeAccessToken method has been updated so as it will not fail in the event that an
	  accessToken has been duplicated, so this method is unnecessary."""
    )
    fun clearDuplicateAccessTokens()

    /**
     * removes duplicate refresh tokens.
     *
     */
    @Deprecated(
        """this method was added to return the remove duplicate refresh token value
	  so that {code removeRefreshToken(OAuth2RefreshTokenEntity o)} would not to fail. the
	  removeRefreshToken method has been updated so as it will not fail in the event that
	  refreshToken has been duplicated, so this method is unnecessary."""
    )
    fun clearDuplicateRefreshTokens()

    fun getAccessTokensForApprovedSite(approvedSite: ApprovedSite): List<OAuth2AccessTokenEntity>
}
