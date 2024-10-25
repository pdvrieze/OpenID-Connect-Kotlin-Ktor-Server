package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.AuthorizationRequest

interface OAuth2RequestFactory {
    suspend fun createAuthorizationRequest(inputParams: Parameters): AuthorizationRequest
    suspend fun createAuthorizationRequest(inputParams: Parameters, client: OAuthClientDetails): AuthorizationRequest
}
