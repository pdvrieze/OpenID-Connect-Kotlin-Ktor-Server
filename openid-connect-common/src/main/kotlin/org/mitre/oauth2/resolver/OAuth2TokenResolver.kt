package org.mitre.oauth2.resolver

import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity

interface OAuth2TokenResolver {
    fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity?
    fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity?
}
