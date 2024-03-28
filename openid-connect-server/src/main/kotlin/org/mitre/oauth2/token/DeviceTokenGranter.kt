/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.oauth2.token

import org.mitre.oauth2.exception.AuthorizationPendingException
import org.mitre.oauth2.exception.DeviceCodeExpiredException
import org.mitre.oauth2.service.DeviceCodeService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.TokenRequest
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices
import org.springframework.stereotype.Component
import java.util.*

/**
 * Implements https://tools.ietf.org/html/draft-ietf-oauth-device-flow
 *
 * @see DeviceEndpoint
 *
 *
 * @author jricher
 */
@Component("deviceTokenGranter")
class DeviceTokenGranter protected constructor(
    tokenServices: AuthorizationServerTokenServices?,
    clientDetailsService: ClientDetailsService?,
    requestFactory: OAuth2RequestFactory?
) : AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE) {
    @Autowired
    private lateinit var deviceCodeService: DeviceCodeService


    /* (non-Javadoc)
	 * @see org.springframework.security.oauth2.provider.token.AbstractTokenGranter#getOAuth2Authentication(org.springframework.security.oauth2.provider.ClientDetails, org.springframework.security.oauth2.provider.TokenRequest)
	 */
    override fun getOAuth2Authentication(client: ClientDetails, tokenRequest: TokenRequest): OAuth2Authentication {
        val deviceCode = tokenRequest.requestParameters["device_code"]

        // look up the device code and consume it
        val dc = deviceCodeService.findDeviceCode(deviceCode!!, client)

        if (dc != null) {
            // make sure the code hasn't expired yet

            if (dc.expiration?.before(Date()) == true) {
                deviceCodeService.clearDeviceCode(deviceCode, client)

                throw DeviceCodeExpiredException("Device code has expired $deviceCode")
            } else if (!dc.isApproved) {
                // still waiting for approval

                throw AuthorizationPendingException("Authorization pending for code $deviceCode")
            } else {
                // inherit the (approved) scopes from the original request
                tokenRequest.setScope(dc.scope)

                val auth =
                    OAuth2Authentication(requestFactory.createOAuth2Request(client, tokenRequest), dc.authenticationHolder!!.userAuth)

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