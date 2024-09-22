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
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.view.CT_JWT
import org.mitre.openid.connect.view.UserInfoJWTView
import org.mitre.openid.connect.view.UserInfoView
import org.mitre.openid.connect.view.userInfoJWTView
import org.mitre.openid.connect.view.userInfoView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientService
import org.mitre.web.util.encryptersService
import org.mitre.web.util.jwtService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import org.mitre.web.util.scopeClaimTranslationService
import org.mitre.web.util.symetricCacheService
import org.mitre.web.util.userInfoService

/**
 * OpenID Connect UserInfo endpoint, as specified in Standard sec 5 and Messages sec 2.4.
 *
 * @author AANGANES
 */
//@Controller
//@RequestMapping("/" + UserInfoEndpoint.URL)
class UserInfoEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        route("/userinfo") {
            get() { getInfo() }
            post { getInfo() }
        }
    }

//    @Autowired
//    private lateinit var userInfoService: UserInfoService

//    @Autowired
//    private lateinit var clientService: ClientDetailsEntityService

    /**
     * Get information about the user as specified in the accessToken included in this request
     */
//    @PreAuthorize("hasRole('ROLE_USER') and #oauth2.hasScope('" + SystemScopeService.OPENID_SCOPE + "')")
//    @RequestMapping(method = [RequestMethod.GET, RequestMethod.POST], produces = [MediaType.APPLICATION_JSON_VALUE, org.mitre.openid.connect.view.UserInfoJWTView.JOSE_MEDIA_TYPE_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.getInfo() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.OPENID_SCOPE) {
            logger.error("getInfo failed; no principal. Requester is not authorized.")
            return
        }

        val claimsRequestJsonString = call.request.queryParameters["claims"]?.takeIf { it.isNotEmpty() }

        val username = auth.name
        val userInfo = userInfoService.getByUsernameAndClientId(username, auth.oAuth2Request.clientId) ?: run {
            logger.error("getInfo failed; user not found: $username")
            return call.respond(HttpStatusCode.NotFound)
        }

        // content negotiation

        // start off by seeing if the client has registered for a signed/encrypted JWT from here
        val client = checkNotNull(clientService.loadClientByClientId(auth.oAuth2Request.clientId))

        val acceptedResponses = getSortedAcceptHeader()

        var respondJWT: Boolean

        if (client.userInfoSignedResponseAlg != null || client.userInfoEncryptedResponseAlg != null || client.userInfoEncryptedResponseEnc != null) {
            // client has a preference, see if they ask for plain JSON specifically on this request
            for (ctq in acceptedResponses) {
                val m = ctq.contentType
                when {
                    m.contentType=="*" || m.contentSubtype=="*" -> {}
                    m.match(CT_JWT) -> { respondJWT = true; break;} // fall back to "default" to avoid duplication

                    m.match(ContentType.Application.Json) -> { respondJWT = false; break; }
                }
            }
            respondJWT = true
        } else {
            // client has no preference, see if they asked for JWT specifically on this request
            for (ctq in acceptedResponses) {
                val m = ctq.contentType
                when {
                    m.contentType == "*" || m.contentSubtype == "*" -> {}
                    m.match(ContentType.Application.Json) -> { respondJWT = false; break; } // fall back to "default" to avoid duplication
                    m.match(CT_JWT) -> { respondJWT = true; break; }
                }
            }
            respondJWT = false
        }

        if (respondJWT) {
            return userInfoJWTView(
                encrypters = encryptersService,
                symmetricCacheService = symetricCacheService,
                userInfo = json.encodeToJsonElement(userInfo).jsonObject,
                client = client,
            )

        } else {
            return userInfoView(
                jwtService = jwtService,
                config = openIdContext.config,
                encrypters = encryptersService,
                symmetricCacheService = symetricCacheService,
                translator = scopeClaimTranslationService,
                userInfo = userInfo,
                scope = auth.oAuth2Request.scope,
                client = client,
                authorizedClaims = auth.oAuth2Request.extensions["claims"],
                requestedClaims = claimsRequestJsonString,
            )
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
