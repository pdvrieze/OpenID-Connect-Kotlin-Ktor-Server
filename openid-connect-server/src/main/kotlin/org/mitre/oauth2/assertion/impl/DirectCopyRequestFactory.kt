package org.mitre.oauth2.assertion.impl

import com.nimbusds.jwt.JWT
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.security.oauth2.provider.TokenRequest
import java.text.ParseException

/**
 * Takes an assertion from a trusted source, looks for the fields:
 *
 * - scope, space-separated list of strings
 * - aud, array of audience IDs
 *
 * @author jricher
 */
class DirectCopyRequestFactory : AssertionOAuth2RequestFactory {

    override fun createOAuth2Request(client: ClientDetails, tokenRequest: TokenRequest, assertion: JWT): OAuth2Request? {
        try {
            val claims = assertion.jwtClaimsSet
            val scope = OAuth2Utils.parseParameterList(claims.getStringClaim("scope"))

            val resources = claims.audience.toSet()

            return OAuth2Request(tokenRequest.requestParameters, client.clientId, client.authorities, true, scope, resources, null, null, null)
        } catch (e: ParseException) {
            return null
        }
    }
}
