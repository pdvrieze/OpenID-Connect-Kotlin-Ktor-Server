package org.mitre.oauth2.service

import kotlinx.serialization.json.JsonObject
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.openid.connect.model.UserInfo

interface JsonIntrospectionResultAssembler : IntrospectionResultAssembler {
    override fun assembleFrom(
        accessToken: OAuth2AccessTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>,
    ): JsonObject

    override fun assembleFrom(
        refreshToken: OAuth2RefreshTokenEntity,
        userInfo: UserInfo?,
        authScopes: Set<String>,
    ): JsonObject
}
