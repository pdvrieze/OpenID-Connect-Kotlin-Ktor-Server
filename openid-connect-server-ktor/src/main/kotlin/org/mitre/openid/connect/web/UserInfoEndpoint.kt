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

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.view.CT_JWT
import org.mitre.openid.connect.view.userInfoJWTView
import org.mitre.openid.connect.view.userInfoView
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.encryptersService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import org.mitre.web.util.scopeClaimTranslationService
import org.mitre.web.util.signService
import org.mitre.web.util.symetricCacheService
import org.mitre.web.util.userInfoService

/**
 * OpenID Connect UserInfo endpoint, as specified in Standard sec 5 and Messages sec 2.4.
 *
 * @author AANGANES
 */
object UserInfoEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        route("/userinfo") {
            get { getInfo() }
            post { getInfo() }
        }
    }

    /**
     * Get information about the user as specified in the accessToken included in this request
     */
    suspend fun RoutingContext.getInfo() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.OPENID_SCOPE) {
            logger.error("getInfo failed; no principal. Requester is not authorized.")
            return
        }

        val claimsRequestJsonString = call.request.queryParameters["claims"]?.takeIf { it.isNotEmpty() }

        val username = auth.name
        val userInfo = userInfoService.getByUsernameAndClientId(username, auth.authorizationRequest.clientId) ?: run {
            logger.error("getInfo failed; user not found: $username")
            return call.respond(HttpStatusCode.NotFound)
        }

        // content negotiation

        // start off by seeing if the client has registered for a signed/encrypted JWT from here
        val client = checkNotNull(clientDetailsService.loadClientByClientId(auth.authorizationRequest.clientId))

        val acceptedResponses = getSortedAcceptHeader()

        var respondJWT: Boolean

        if (client.userInfoSignedResponseAlg != null || client.userInfoEncryptedResponseAlg != null || client.userInfoEncryptedResponseEnc != null) {
            // client has a preference, see if they ask for plain JSON specifically on this request
            respondJWT = true
            for (ctq in acceptedResponses) {
                val m = ctq.contentType
                when {
                    m.contentType=="*" || m.contentSubtype=="*" -> {}
                    m.match(CT_JWT) -> { respondJWT = true; break;} // fall back to "default" to avoid duplication

                    m.match(ContentType.Application.Json) -> { respondJWT = false; break; }
                }
            }
        } else {
            // client has no preference, see if they asked for JWT specifically on this request
            respondJWT = false
            for (ctq in acceptedResponses) {
                val m = ctq.contentType
                when {
                    m.contentType == "*" || m.contentSubtype == "*" -> {}
                    m.match(ContentType.Application.Json) -> { respondJWT = false; break; } // fall back to "default" to avoid duplication
                    m.match(CT_JWT) -> { respondJWT = true; break; }
                }
            }
        }

        if (respondJWT) {
            return userInfoJWTView(
                encrypters = encryptersService,
                symmetricCacheService = symetricCacheService,
                userInfo = oidJson.encodeToJsonElement(userInfo).jsonObject,
                client = client,
            )

        } else {
            val oidRequest = auth.authorizationRequest as? OpenIdAuthorizationRequest
            return userInfoView(
                jwtService = signService,
                config = openIdContext.config,
                encrypters = encryptersService,
                symmetricCacheService = symetricCacheService,
                translator = scopeClaimTranslationService,
                userInfo = userInfo,
                scope = auth.authorizationRequest.scope,
                client = client,
                authorizedClaims = oidRequest?.requestedClaims?.toString(),
                requestedClaims = claimsRequestJsonString,
            )
        }
    }

    const val URL: String = "userinfo"

    /**
     * Logger for this class
     */
    private val logger = getLogger<UserInfoEndpoint>()
}
