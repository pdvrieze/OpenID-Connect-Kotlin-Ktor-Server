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

import io.github.pdvrieze.auth.ClientSecretAuthentication
import io.github.pdvrieze.auth.OpenIdAuthentication
import io.github.pdvrieze.auth.TokenAuthentication
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.InvalidTokenException
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.JsonIntrospectionResultAssembler
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.model.UserInfo
import org.mitre.openid.connect.view.jsonEntityView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.OpenIdContextPlugin
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.resolveAuthenticatedUser
import org.mitre.web.util.resourceSetService
import org.mitre.web.util.tokenService
import org.mitre.web.util.userInfoService


object IntrospectionEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        authenticate {
            get("/introspection") {
                val tokenValue = call.request.queryParameters["token"]
                val tokenType = call.request.queryParameters["token_type_hint"]
                verify(tokenType, tokenValue)
            }

        }
    }

    val RoutingContext.openIdContext
        get() = call.application.plugin(OpenIdContextPlugin).context

    suspend fun RoutingContext.verify(
        tokenValue: String?,
        tokenType: String?,
    ) {
        val auth  = resolveAuthenticatedUser() ?: return call.respond(HttpStatusCode.Unauthorized)
        val introspectionResultAssembler: JsonIntrospectionResultAssembler = openIdContext.introspectionResultAssembler
        val authClient: OAuthClientDetails
        val authScopes: MutableSet<String> = HashSet()

        if (auth is TokenAuthentication) {
            // the client authenticated with OAuth, do our UMA checks
            AuthenticationUtilities.ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

            // get out the client that was issued the access token (not the token being introspected)
            val o2a = auth

            val authClientId = o2a.clientId
            authClient = checkNotNull(clientDetailsService.loadClientByClientId(authClientId))

            // the owner is the user who authorized the token in the first place
            val ownerId = o2a.principalName

            authClient.scope?.let { authScopes.addAll(it) }

            // UMA style clients also get a subset of scopes of all the resource sets they've registered
            val resourceSets = resourceSetService.getAllForOwnerAndClient(ownerId, authClientId)

            // collect all the scopes
            for (rs in resourceSets) {
                authScopes.addAll(rs.scopes)
            }
        } else {
            if (auth !is ClientSecretAuthentication) {
                return call.respond(HttpStatusCode.BadRequest)
            }
            // the client authenticated directly, make sure it's got the right access

            val authClientId =
                auth.clientId // direct authentication puts the client_id into the authentication's name field
            authClient = checkNotNull(clientDetailsService.loadClientByClientId(authClientId))

            // directly authenticated clients get a subset of any scopes that they've registered for
            authClient.scope?.let { authScopes.addAll(it) }

            if (!AuthenticationUtilities.hasRole(auth, GrantedAuthority.ROLE_CLIENT)
                || !authClient.isAllowIntrospection
            ) {
                // this client isn't allowed to do direct introspection

                logger.error("Client ${authClient.clientId} is not allowed to call introspection endpoint")
                return call.respond(HttpStatusCode.Forbidden)
            }
        }

        // by here we're allowed to introspect, now we need to look up the token in our token stores

        // first make sure the token is there
        if (tokenValue.isNullOrEmpty()) {
            logger.error("Verify failed; token value is null")
            return jsonEntityView(active = false)
        }

        var accessToken: OAuth2AccessTokenEntity? = null
        var refreshToken: OAuth2RefreshTokenEntity? = null
        var tokenClient: OAuthClientDetails?
        var user: UserInfo?

        try {
            // check access tokens first (includes ID tokens)

            accessToken = tokenService.readAccessToken(tokenValue)

            tokenClient = accessToken.client

            // get the user information of the user that authorized this token in the first place
            val userName = accessToken.authenticationHolder.principalName
            user = openIdContext.userInfoService.getByUsernameAndClientId(userName, tokenClient!!.clientId)
        } catch (e: InvalidTokenException) {
            logger.info("Invalid access token. Checking refresh token.")
            try {
                // check refresh tokens next

                refreshToken = tokenService.getRefreshToken(tokenValue)

                tokenClient = refreshToken.client

                // get the user information of the user that authorized this token in the first place
                val userName = refreshToken.authenticationHolder.principalName
                user = userInfoService.getByUsernameAndClientId(userName, tokenClient!!.clientId)
            } catch (e2: InvalidTokenException) {
                logger.error("Invalid refresh token")
                return jsonEntityView(active = false)
            }
        }

        // if it's a valid token, we'll print out information on it
        if (accessToken != null) {
            return call.respondJson(introspectionResultAssembler.assembleFrom(accessToken, user, authScopes))
        } else if (refreshToken != null) {
            return call.respondJson(introspectionResultAssembler.assembleFrom(refreshToken, user, authScopes))
        }

        logger.error("Verify failed; Invalid access/refresh token")
        // no tokens were found (we shouldn't get here)
        return jsonEntityView(active = false)
    }

    const val URL: String = "introspect"

    /**
     * Logger for this class
     */
    private val logger = getLogger<IntrospectionEndpoint>()
}
