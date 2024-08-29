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
package org.mitre.oauth2.web

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class RevocationEndpoint {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var tokenServices: OAuth2TokenEntityService

    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CLIENT')")
    @RequestMapping("/" + URL)
    fun revoke(
        @RequestParam("token") tokenValue: String,
        @RequestParam(value = "token_type_hint", required = false) tokenType: String?,
        auth: Authentication,
        model: Model
    ): String {
        // This is the token as passed in from OAuth (in case we need it some day)
        //OAuth2AccessTokenEntity tok = tokenServices.getAccessToken((OAuth2Authentication) principal);

        val authClient: OAuthClientDetails?

        if (auth is OAuth2Authentication) {
            // the client authenticated with OAuth, do our UMA checks
            AuthenticationUtilities.ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)
            // get out the client that was issued the access token (not the token being revoked)
            val o2a = auth

            val authClientId = o2a.oAuth2Request.clientId
            authClient = clientService.loadClientByClientId(authClientId)

            // the owner is the user who authorized the token in the first place
            val ownerId = o2a.userAuthentication.name
        } else {
            // the client authenticated directly, make sure it's got the right access

            val authClientId =
                auth.name // direct authentication puts the client_id into the authentication's name field
            authClient = clientService.loadClientByClientId(authClientId)
        }

        try {
            // check and handle access tokens first

            val accessToken = tokenServices.readAccessToken(tokenValue)

            // client acting on its own, make sure it owns the token
            if (accessToken.client!!.getClientId() != authClient!!.getClientId()) {
                // trying to revoke a token we don't own, throw a 403

                logger.info("Client ${authClient.getClientId()} tried to revoke a token owned by ${accessToken.client!!.getClientId()}")

                model.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return HttpCodeView.VIEWNAME
            }

            // if we got this far, we're allowed to do this
            tokenServices.revokeAccessToken(accessToken)

            logger.debug("Client ${authClient.getClientId()} revoked access token $tokenValue")

            model.addAttribute(HttpCodeView.CODE, HttpStatus.OK)
            return HttpCodeView.VIEWNAME
        } catch (e: InvalidTokenException) {
            // access token wasn't found, check the refresh token

            try {
                val refreshToken = tokenServices.getRefreshToken(tokenValue)
                // client acting on its own, make sure it owns the token
                if (refreshToken!!.client!!.getClientId() != authClient!!.getClientId()) {
                    // trying to revoke a token we don't own, throw a 403

                    logger.info("Client ${authClient.getClientId()} tried to revoke a token owned by ${refreshToken.client!!.getClientId()}")

                    model.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                    return HttpCodeView.VIEWNAME
                }

                // if we got this far, we're allowed to do this
                tokenServices.revokeRefreshToken(refreshToken)

                logger.debug("Client ${authClient.getClientId()} revoked access token $tokenValue")

                model.addAttribute(HttpCodeView.CODE, HttpStatus.OK)
                return HttpCodeView.VIEWNAME
            } catch (e1: InvalidTokenException) {
                // neither token type was found, simply say "OK" and be on our way.

                logger.debug("Failed to revoke token $tokenValue")

                model.addAttribute(HttpCodeView.CODE, HttpStatus.OK)
                return HttpCodeView.VIEWNAME
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<RevocationEndpoint>()

        const val URL: String = "revoke"
    }
}
