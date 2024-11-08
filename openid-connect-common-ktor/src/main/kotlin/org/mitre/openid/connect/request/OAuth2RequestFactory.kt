package org.mitre.openid.connect.request

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest

interface OAuth2RequestFactory {
    suspend fun createAuthorizationRequest(inputParams: Map<String, String>): AuthorizationRequest
    suspend fun createAuthorizationRequest(inputParams: Map<String, String>, client: OAuthClientDetails): AuthorizationRequest
}
