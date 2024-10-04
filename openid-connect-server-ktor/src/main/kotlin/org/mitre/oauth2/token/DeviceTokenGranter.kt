package org.mitre.oauth2.token

import org.mitre.oauth2.exception.AuthorizationPendingException
import org.mitre.oauth2.exception.DeviceCodeExpiredException
import org.mitre.oauth2.exception.InvalidGrantException
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.service.DeviceCodeService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.request.OAuth2RequestFactory
import java.util.*

/**
 * Implements https://tools.ietf.org/html/draft-ietf-oauth-device-flow
 *
 * @see DeviceEndpoint
 *
 *
 * @author jricher
 */
class DeviceTokenGranter protected constructor(
    tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    private val deviceCodeService: DeviceCodeService,
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE) {

    /* (non-Javadoc)
         * @see org.springframework.security.oauth2.provider.token.AbstractTokenGranter#getOAuth2Authentication(org.springframework.security.oauth2.provider.ClientDetails, org.springframework.security.oauth2.provider.TokenRequest)
         */
    override suspend fun getOAuth2Authentication(
        client: OAuthClientDetails,
        tokenRequest: TokenRequest,
    ): OAuth2RequestAuthentication {
        val deviceCode = tokenRequest.requestParameters["device_code"]

        // look up the device code and consume it
        val dc = deviceCodeService.findDeviceCode(deviceCode!!, client)

        if (dc != null) {
            // make sure the code hasn't expired yet

            if (dc.expiration?.before(Date()) == true) {
                deviceCodeService.clearDeviceCode(deviceCode, client)

                throw DeviceCodeExpiredException("Device code has expired $deviceCode")
            } else if (dc.isApproved != true) {
                // still waiting for approval

                throw AuthorizationPendingException("Authorization pending for code $deviceCode")
            } else {
                // inherit the (approved) scopes from the original request
                tokenRequest.scope = dc.scope

                val userAuth = dc.authenticationHolder?.userAuth?.let { a -> SavedUserAuthentication.from(a) }
                val auth =
                    OAuth2RequestAuthentication(requestFactory.createAuthorizationRequest(tokenRequest.requestParameters), userAuth)

                deviceCodeService.clearDeviceCode(deviceCode, client)

                return auth
            }
        } else {
            throw InvalidGrantException("Invalid device code: $deviceCode")
        }
    }


    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant-type:device_code"
    }
}
