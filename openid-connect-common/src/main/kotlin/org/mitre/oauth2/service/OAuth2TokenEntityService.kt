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
package org.mitre.oauth2.service

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices

interface OAuth2TokenEntityService : AuthorizationServerTokenServices, ResourceServerTokenServices {
    override fun readAccessToken(accessTokenValue: String): OAuth2AccessTokenEntity

    fun getRefreshToken(refreshTokenValue: String): OAuth2RefreshTokenEntity?

    fun revokeRefreshToken(refreshToken: OAuth2RefreshTokenEntity)

    fun revokeAccessToken(accessToken: OAuth2AccessTokenEntity)

    fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity>

    fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity>

    fun clearExpiredTokens()

    fun saveAccessToken(accessToken: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity

    fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity

    override fun getAccessToken(authentication: OAuth2Authentication): OAuth2AccessTokenEntity

    fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity?

    fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity?

    fun getAllAccessTokensForUser(name: String): Set<OAuth2AccessTokenEntity>

    fun getAllRefreshTokensForUser(name: String): Set<OAuth2RefreshTokenEntity>

    fun getRegistrationAccessTokenForClient(client: OAuthClientDetails): OAuth2AccessTokenEntity?
}
