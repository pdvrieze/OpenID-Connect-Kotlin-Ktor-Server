package org.mitre.oauth2

import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication

interface TokenEnhancer {
    suspend fun enhance(accessToken: OAuth2AccessToken.Builder, authentication: OAuth2RequestAuthentication)
}
