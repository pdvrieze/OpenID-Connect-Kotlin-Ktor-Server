package org.mitre.oauth2

import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2Authentication

interface TokenEnhancer {
    fun enhance(accessToken: OAuth2AccessToken.Builder, authentication: OAuth2Authentication)
}
