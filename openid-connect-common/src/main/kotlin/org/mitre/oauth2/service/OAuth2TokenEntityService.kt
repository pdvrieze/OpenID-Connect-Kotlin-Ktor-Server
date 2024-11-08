package org.mitre.oauth2.service

import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.resolver.OAuth2TokenResolver

interface OAuth2TokenEntityService : OAuth2TokenResolver {

    //region Custom functions
    fun getRefreshToken(refreshTokenValue: String): OAuth2RefreshTokenEntity

    fun revokeRefreshToken(refreshToken: OAuth2RefreshTokenEntity)

    fun revokeAccessToken(accessToken: OAuth2AccessTokenEntity)

    fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity>

    fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity>

    fun clearExpiredTokens()

    fun saveAccessToken(accessToken: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity

    fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity

    fun getAllAccessTokensForUser(name: String): Set<OAuth2AccessTokenEntity>

    fun getAllRefreshTokensForUser(name: String): Set<OAuth2RefreshTokenEntity>

    fun getRegistrationAccessTokenForClient(client: OAuthClientDetails): OAuth2AccessTokenEntity?
    //endregion

    //region Authorization Server
    suspend fun createAccessToken(
        authentication: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean,
        requestParameters: Map<String, String>
    ): OAuth2AccessToken

    suspend fun refreshAccessToken(refreshTokenValue: String, tokenRequest: AuthorizationRequest /*TokenRequest*/): OAuth2AccessToken

    fun getAccessToken(authentication: AuthenticatedAuthorizationRequest): OAuth2AccessToken
    //endregion

    //region Resource server
    fun readAccessToken(accessTokenValue: String): OAuth2AccessTokenEntity

    fun loadAuthentication(accessToken: String): AuthenticatedAuthorizationRequest
    //endregion

}
