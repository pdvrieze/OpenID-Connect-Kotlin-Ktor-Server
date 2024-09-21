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
import io.ktor.server.sessions.*
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlApproveView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientService
import org.mitre.web.util.redirectResolver
import org.mitre.web.util.requireRole
import org.mitre.web.util.resolveAuthenticatedUser
import org.mitre.web.util.scopeClaimTranslationService
import org.mitre.web.util.scopeService
import org.mitre.web.util.statsService
import org.mitre.web.util.userInfoService
import java.net.URISyntaxException
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * @author jricher
 */
//@SessionAttributes("authorizationRequest")
class OAuthConfirmationController: KtorEndpoint {

    override fun Route.addRoutes() {
        confirmAccess()
    }

    private fun Route.confirmAccess() {
        authenticate {
            get("/oauth/confirm_access") {
                val authentication = requireRole(GrantedAuthority.ROLE_USER) { return@get }

                val authRequest: OAuth2Request = call.sessions.get<OpenIdSessionStorage>()?.authorizationRequest
                    ?: return@get call.respond(HttpStatusCode.BadRequest)

                // Check the "prompt" parameter to see if we need to do special processing
                val prompt = authRequest.extensions.get(ConnectRequestParameters.PROMPT)
                val prompts = prompt?.split(ConnectRequestParameters.PROMPT_SEPARATOR)?: emptyList()

                val client: OAuthClientDetails?
                try {
                    client = clientService.loadClientByClientId(authRequest.clientId)
                } catch (e: OAuth2Exception) {
                    logger.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e)
                    return@get call.respond(HttpStatusCode.BadRequest)
                } catch (e: IllegalArgumentException) {
                    logger.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e)
                    return@get call.respond(HttpStatusCode.BadRequest)
                }

                if (client == null) {
                    logger.error("confirmAccess: could not find client ${authRequest.clientId}")
                    return@get call.respond(HttpStatusCode.NotFound)
                }

                if (prompts.contains("none")) {
                    // if we've got a redirect URI then we'll send it
                    // TODO no longer use spring, remove cast
                    val url = authRequest.redirectUri?.let{ redirectResolver.resolveRedirect(it, client) }
                        ?:return@get call.respond(HttpStatusCode.Forbidden)

                    try {
                        val uriBuilder = URLBuilder(url)

                        uriBuilder.parameters["error"] = "interaction_required"
                        if (authRequest.state.isNotEmpty()) {
                            uriBuilder.parameters["state"] = authRequest.state // copy the state parameter if one was given
                        }
                        return@get call.respondRedirect(uriBuilder.build())
                    } catch (e: URISyntaxException) {
                        logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                        return@get call.respond(HttpStatusCode.Forbidden)
                    }
                }

                val redirect_uri = authRequest.redirectUri


                // pre-process the scopes
                val scopes: Set<SystemScope>? = scopeService.fromStrings(authRequest.scope)

                val sortedScopes: MutableSet<SystemScope> = LinkedHashSet(scopes!!.size)
                val systemScopes: Set<SystemScope> = scopeService.all

                // sort scopes for display based on the inherent order of system scopes
                for (s in systemScopes) {
                    if (scopes.contains(s)) {
                        sortedScopes.add(s)
                    }
                }

                // add in any scopes that aren't system scopes to the end of the list
                sortedScopes.addAll(scopes - systemScopes)

                // get the userinfo claims for each scope
                val user = userInfoService.getByUsername(authentication.name)
                val claimsForScopes: MutableMap<String?, Map<String, String>> = HashMap()
                if (user != null) {
                    val userJson = user.toJson()

                    for (systemScope in sortedScopes) {
                        val claimValues: MutableMap<String, String> = HashMap()
                        val scopeValue = systemScope.value!!

                        val claims = scopeClaimTranslationService.getClaimsForScope(scopeValue)
                        for (claim in claims!!) {
                            (userJson[claim] as? JsonPrimitive)?.let {
                                // TODO: this skips the address claim
                                claimValues[claim] = it.toString()
                            }
                        }

                        claimsForScopes[scopeValue] = claimValues
                    }
                }

                // client stats
                val count = statsService.getCountForClientId(client.clientId!!)!!.approvedSiteCount ?: 0

                // if the client is over a week old and has more than one registration, don't give such a big warning
                // instead, tag as "Generally Recognized As Safe" (gras)
                val lastWeek = Instant.now().minus(1, ChronoUnit.WEEKS)
                val createdAt = client.createdAt
                val gras = count > 1 && createdAt != null && createdAt.toInstant().isBefore(lastWeek)

                htmlApproveView(
                    authRequest = authRequest,
                    client = client,
                    redirectUri = redirect_uri,
                    scopes = sortedScopes,
                    claims = claimsForScopes,
                    approvedSiteCount = count,
                    contacts = client.contacts?.joinToString(),
                    isGras = gras,
                )
            }
        }
    }


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<OAuthConfirmationController>()
    }
}
