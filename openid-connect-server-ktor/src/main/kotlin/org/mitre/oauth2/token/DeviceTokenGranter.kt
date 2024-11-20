package org.mitre.oauth2.token

import org.mitre.oauth2.exception.AuthorizationPendingException
import org.mitre.oauth2.exception.DeviceCodeExpiredException
import org.mitre.oauth2.exception.InvalidGrantException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.request.AuthorizationRequest
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
class DeviceTokenGranter constructor(
    tokenServices: OAuth2TokenEntityService,
    clientDetailsService: ClientResolver,
    requestFactory: OAuth2RequestFactory,
    val deviceCodeService: DeviceCodeService,
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE) {
    override val isGrantAllowsRefresh: Boolean get() = true

    override suspend fun getAccessToken(
        client: OAuthClientDetails,
        tokenRequest: AuthenticatedAuthorizationRequest,
        isAllowRefresh: Boolean,
        requestParameters: Map<String, String>,
    ): OAuth2AccessToken {
        val deviceCode = requestParameters["device_code"]

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
                check(tokenRequest.authorizationRequest.scope == dc.scope)

                // inherit the (approved) scopes from the original request
//                requestBuilder.scope = dc.scope ?: emptySet() // TODO

//                val userAuth = dc.authenticationHolder?.userAuthentication?.let { a -> SavedUserAuthentication.from(a) }
//                val auth =
//                    AuthenticatedAuthorizationRequest(requestFactory.createOAuth2Request(client, finalTokenRequest).fromSpring(), userAuth)

                deviceCodeService.clearDeviceCode(deviceCode, client)

//                return auth.toSpring()
            }
        } else {
            throw InvalidGrantException("Invalid device code: $deviceCode")
        }


        return super.getAccessToken(client, tokenRequest, isAllowRefresh, requestParameters)
    }

    override suspend fun grant(
        grantType: String,
        request: AuthorizationRequest,
        authenticatedClient: OAuthClientDetails,
        requestParameters: Map<String, String>,
    ): OAuth2AccessToken {
        return super.grant(grantType, request, authenticatedClient, requestParameters)
    }

    companion object {
        const val GRANT_TYPE: String = "urn:ietf:params:oauth:grant-type:device_code"
    }
}
