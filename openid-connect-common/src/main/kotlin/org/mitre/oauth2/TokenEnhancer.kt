package org.mitre.oauth2

import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken

interface TokenEnhancer {
    suspend fun enhance(accessToken: OAuth2AccessToken.Builder, authentication: AuthenticatedAuthorizationRequest)
}
