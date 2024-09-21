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

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.InvalidTokenException
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2Authentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.web.AuthenticationUtilities.hasRole
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientService
import org.mitre.web.util.requireRole
import org.mitre.web.util.requireRoleOf
import org.mitre.web.util.resolveAuthenticatedUser
import org.mitre.web.util.tokenService

class RevocationEndpoint : KtorEndpoint {

    override fun Route.addRoutes() {
        revoke()
    }

    private fun Route.revoke() {
        authenticate {
            get("/revoke") {
                val auth = requireRoleOf(GrantedAuthority.ROLE_ADMIN, GrantedAuthority.ROLE_CLIENT) { return@get }

                val tokenValue = call.request.queryParameters["token"]
                    ?: return@get call.respond(HttpStatusCode.BadRequest)
                val tokenType = call.request.queryParameters["token_type_hint"]

                val authClient: OAuthClientDetails

                val clientService = clientService

                if (auth is OAuth2Authentication) {
                    // the client authenticated with OAuth, do our UMA checks
                    AuthenticationUtilities.ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)
                    // get out the client that was issued the access token (not the token being revoked)
                    val o2a = auth

                    val authClientId = o2a.oAuth2Request.clientId
                    authClient = clientService.loadClientByClientId(authClientId)
                        ?: return@get call.respond(HttpStatusCode.BadRequest)

                    // the owner is the user who authorized the token in the first place
                    val ownerId = o2a.userAuthentication?.name
                } else {
                    // the client authenticated directly, make sure it's got the right access

                    // direct authentication puts the client_id into the authentication's name field
                    val authClientId = auth.name
                    authClient = clientService.loadClientByClientId(authClientId)
                        ?: return@get call.respond(HttpStatusCode.BadRequest)

                }

                try {
                    // check and handle access tokens first

                    val accessToken = tokenService.readAccessToken(tokenValue)

                    // client acting on its own, make sure it owns the token
                    if (accessToken.client!!.clientId != authClient.clientId) {
                        // trying to revoke a token we don't own, throw a 403

                        logger.info("Client ${authClient.clientId} tried to revoke a token owned by ${accessToken.client!!.clientId}")
                        return@get call.respond(HttpStatusCode.Forbidden)
                    }

                    // if we got this far, we're allowed to do this
                    tokenService.revokeAccessToken(accessToken)

                    logger.debug("Client ${authClient.clientId} revoked access token $tokenValue")
                    return@get call.respond(HttpStatusCode.OK)
                } catch (e: InvalidTokenException) {
                    // access token wasn't found, check the refresh token

                    try {
                        val refreshToken = tokenService.getRefreshToken(tokenValue)
                        // client acting on its own, make sure it owns the token
                        if (refreshToken.client?.clientId != authClient.clientId) {
                            // trying to revoke a token we don't own, throw a 403

                            logger.info("Client ${authClient.clientId} tried to revoke a token owned by ${refreshToken.client!!.clientId}")
                            return@get call.respond(HttpStatusCode.Forbidden)
                        }


                        // if we got this far, we're allowed to do this
                        tokenService.revokeRefreshToken(refreshToken)

                        logger.debug("Client ${authClient.clientId} revoked access token $tokenValue")
                        return@get call.respond(HttpStatusCode.OK)
                    } catch (e1: InvalidTokenException) {
                        // neither token type was found, simply say "OK" and be on our way.

                        logger.debug("Failed to revoke token $tokenValue")
                        return@get call.respond(HttpStatusCode.OK)
                    }
                }


            }

        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<RevocationEndpoint>()

    }
}
