package org.mitre.openid.connect.request

import io.ktor.http.*
import org.mitre.oauth2.model.convert.OAuth2Request

interface OAuth2RequestFactory {
    open fun createAuthorizationRequest(inputParams: Parameters): OAuth2Request
}
