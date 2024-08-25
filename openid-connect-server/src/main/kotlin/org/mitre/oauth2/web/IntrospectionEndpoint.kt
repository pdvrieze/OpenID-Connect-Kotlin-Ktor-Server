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

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.IntrospectionResultAssembler
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.uma.service.ResourceSetService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class IntrospectionEndpoint {
    @Autowired
    private lateinit var tokenServices: OAuth2TokenEntityService

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var introspectionResultAssembler: IntrospectionResultAssembler

    @Autowired
    private lateinit var userInfoService: UserInfoService

    @Autowired
    private lateinit var resourceSetService: ResourceSetService

    constructor()

    constructor(tokenServices: OAuth2TokenEntityService) {
        this.tokenServices = tokenServices
    }

    @RequestMapping("/" + URL)
    fun verify(
        @RequestParam("token") tokenValue: String?,
        @RequestParam(value = "token_type_hint", required = false) tokenType: String?,
        auth: Authentication, model: Model
    ): String {
        var authClient: OAuthClientDetails
        val authScopes: MutableSet<String> = HashSet()

        if (auth is OAuth2Authentication) {
            // the client authenticated with OAuth, do our UMA checks
            AuthenticationUtilities.ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

            // get out the client that was issued the access token (not the token being introspected)
            val o2a = auth

            val authClientId = o2a.oAuth2Request.clientId
            authClient = checkNotNull(clientService.loadClientByClientId(authClientId))

            // the owner is the user who authorized the token in the first place
            val ownerId = o2a.userAuthentication.name

            authScopes.addAll(authClient.getScope())

            // UMA style clients also get a subset of scopes of all the resource sets they've registered
            val resourceSets = resourceSetService.getAllForOwnerAndClient(ownerId, authClientId)

            // collect all the scopes
            for (rs in resourceSets) {
                authScopes.addAll(rs.scopes)
            }
        } else {
            // the client authenticated directly, make sure it's got the right access

            val authClientId =
                auth.name // direct authentication puts the client_id into the authentication's name field
            authClient = checkNotNull(clientService.loadClientByClientId(authClientId))

            // directly authenticated clients get a subset of any scopes that they've registered for
            authScopes.addAll(authClient.getScope())

            if (!AuthenticationUtilities.hasRole(auth, "ROLE_CLIENT")
                || !authClient.isAllowIntrospection
            ) {
                // this client isn't allowed to do direct introspection

                logger.error("Client ${authClient.getClientId()} is not allowed to call introspection endpoint")
                model.addAttribute("code", HttpStatus.FORBIDDEN)
                return HttpCodeView.VIEWNAME
            }
        }

        // by here we're allowed to introspect, now we need to look up the token in our token stores

        // first make sure the token is there
        if (tokenValue.isNullOrEmpty()) {
            logger.error("Verify failed; token value is null")
            val entity: Map<String, Boolean> = mapOf("active" to java.lang.Boolean.FALSE)
            model.addAttribute(JsonEntityView.ENTITY, entity)
            return JsonEntityView.VIEWNAME
        }

        var accessToken: OAuth2AccessTokenEntity? = null
        var refreshToken: OAuth2RefreshTokenEntity? = null
        var tokenClient: OAuthClientDetails?
        var user: UserInfo?

        try {
            // check access tokens first (includes ID tokens)

            accessToken = tokenServices.readAccessToken(tokenValue)

            tokenClient = accessToken.client

            // get the user information of the user that authorized this token in the first place
            val userName = accessToken.authenticationHolder.authentication.name
            user = userInfoService.getByUsernameAndClientId(userName, tokenClient!!.getClientId()!!)
        } catch (e: InvalidTokenException) {
            logger.info("Invalid access token. Checking refresh token.")
            try {
                // check refresh tokens next

                refreshToken = tokenServices.getRefreshToken(tokenValue)

                tokenClient = refreshToken!!.client

                // get the user information of the user that authorized this token in the first place
                val userName = refreshToken.authenticationHolder.authentication.name
                user = userInfoService.getByUsernameAndClientId(userName, tokenClient!!.getClientId()!!)
            } catch (e2: InvalidTokenException) {
                logger.error("Invalid refresh token")
                val entity: Map<String, Boolean> =
                    mapOf(IntrospectionResultAssembler.ACTIVE to java.lang.Boolean.FALSE)
                model.addAttribute(JsonEntityView.ENTITY, entity)
                return JsonEntityView.VIEWNAME
            }
        }

        // if it's a valid token, we'll print out information on it
        if (accessToken != null) {
            val entity = introspectionResultAssembler.assembleFrom(accessToken, user, authScopes)
            model.addAttribute(JsonEntityView.ENTITY, entity)
        } else if (refreshToken != null) {
            val entity = introspectionResultAssembler.assembleFrom(refreshToken, user, authScopes)
            model.addAttribute(JsonEntityView.ENTITY, entity)
        } else {
            // no tokens were found (we shouldn't get here)
            logger.error("Verify failed; Invalid access/refresh token")
            val entity: Map<String, Boolean> =
                mapOf(IntrospectionResultAssembler.ACTIVE to java.lang.Boolean.FALSE)
            model.addAttribute(JsonEntityView.ENTITY, entity)
            return JsonEntityView.VIEWNAME
        }

        return JsonEntityView.VIEWNAME
    }

    companion object {
        const val URL: String = "introspect"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(IntrospectionEndpoint::class.java)
    }
}
