package org.mitre.oauth2.assertion

import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.convert.AuthorizationRequest

/**
 * Take in an assertion and token request and generate an OAuth2Request from it, including scopes and other important components
 *
 * @author jricher
 */
interface AssertionOAuth2RequestFactory {
    fun createOAuth2Request(client: OAuthClientDetails, tokenRequest: org.mitre.oauth2.token.TokenRequest, assertion: JWT): AuthorizationRequest?
}
