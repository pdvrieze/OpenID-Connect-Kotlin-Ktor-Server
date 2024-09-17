/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
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
package org.mitre.openid.connect.web

import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.UserInfoJWTView
import org.mitre.openid.connect.view.UserInfoView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam

/**
 * OpenID Connect UserInfo endpoint, as specified in Standard sec 5 and Messages sec 2.4.
 *
 * @author AANGANES
 */
@Controller
@RequestMapping("/" + UserInfoEndpoint.URL)
class UserInfoEndpoint {
    @Autowired
    private lateinit var userInfoService: UserInfoService

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    /**
     * Get information about the user as specified in the accessToken included in this request
     */
    @PreAuthorize("hasRole('ROLE_USER') and #oauth2.hasScope('" + SystemScopeService.OPENID_SCOPE + "')")
    @RequestMapping(method = [RequestMethod.GET, RequestMethod.POST], produces = [MediaType.APPLICATION_JSON_VALUE, org.mitre.openid.connect.view.UserInfoJWTView.JOSE_MEDIA_TYPE_VALUE])
    fun getInfo(
        @RequestParam(value = "claims", required = false) claimsRequestJsonString: String?,
        @RequestHeader(value = HttpHeaders.ACCEPT, required = false) acceptHeader: String?,
        auth: OAuth2Authentication?,
        model: Model
    ): String {
        if (auth == null) {
            logger.error("getInfo failed; no principal. Requester is not authorized.")
            model.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        val username = auth.name
        val userInfo = userInfoService.getByUsernameAndClientId(username, auth.oAuth2Request.clientId)

        if (userInfo == null) {
            logger.error("getInfo failed; user not found: $username")
            model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        model.addAttribute(org.mitre.openid.connect.view.UserInfoView.SCOPE, auth.oAuth2Request.scope)

        model.addAttribute(org.mitre.openid.connect.view.UserInfoView.AUTHORIZED_CLAIMS, auth.oAuth2Request.extensions["claims"])

        if (!claimsRequestJsonString.isNullOrEmpty()) {
            model.addAttribute(org.mitre.openid.connect.view.UserInfoView.REQUESTED_CLAIMS, claimsRequestJsonString)
        }

        model.addAttribute(org.mitre.openid.connect.view.UserInfoView.USER_INFO, userInfo)

        // content negotiation

        // start off by seeing if the client has registered for a signed/encrypted JWT from here
        val client = checkNotNull(clientService.loadClientByClientId(auth.oAuth2Request.clientId))
        model.addAttribute(org.mitre.openid.connect.view.UserInfoJWTView.CLIENT, client)

        val mediaTypes = MediaType.parseMediaTypes(acceptHeader)
        MediaType.sortBySpecificityAndQuality(mediaTypes)

        if (client.userInfoSignedResponseAlg != null || client.userInfoEncryptedResponseAlg != null || client.userInfoEncryptedResponseEnc != null) {
            // client has a preference, see if they ask for plain JSON specifically on this request
            for (m in mediaTypes) {
                if (!m.isWildcardType && m.isCompatibleWith(org.mitre.openid.connect.view.UserInfoJWTView.JOSE_MEDIA_TYPE)) {
                    return org.mitre.openid.connect.view.UserInfoJWTView.VIEWNAME
                } else if (!m.isWildcardType && m.isCompatibleWith(MediaType.APPLICATION_JSON)) {
                    return org.mitre.openid.connect.view.UserInfoView.VIEWNAME
                }
            }

            // otherwise return JWT
            return org.mitre.openid.connect.view.UserInfoJWTView.VIEWNAME
        } else {
            // client has no preference, see if they asked for JWT specifically on this request
            for (m in mediaTypes) {
                if (!m.isWildcardType && m.isCompatibleWith(MediaType.APPLICATION_JSON)) {
                    return org.mitre.openid.connect.view.UserInfoView.VIEWNAME
                } else if (!m.isWildcardType && m.isCompatibleWith(org.mitre.openid.connect.view.UserInfoJWTView.JOSE_MEDIA_TYPE)) {
                    return org.mitre.openid.connect.view.UserInfoJWTView.VIEWNAME
                }
            }

            // otherwise return JSON
            return org.mitre.openid.connect.view.UserInfoView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = "userinfo"

        /**
         * Logger for this class
         */
        private val logger = getLogger<UserInfoEndpoint>()
    }
}
