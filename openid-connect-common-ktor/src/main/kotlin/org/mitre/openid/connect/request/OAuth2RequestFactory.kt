package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.OAuth2Request

interface OAuth2RequestFactory {
    suspend fun createAuthorizationRequest(inputParams: Parameters): OAuth2Request
    suspend fun createAuthorizationRequest(inputParams: Parameters, client: OAuthClientDetails): OAuth2Request
}
