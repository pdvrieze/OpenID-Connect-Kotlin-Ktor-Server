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
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.openid.connect.request.Prompt
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlApproveView
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.requireRole
import org.mitre.web.util.scopeClaimTranslationService
import org.mitre.web.util.scopeService
import org.mitre.web.util.statsService
import org.mitre.web.util.userInfoService
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * @author jricher
 */
//@SessionAttributes("authorizationRequest")
object OAuthConfirmationController/*: KtorEndpoint*/ {

/*
    override fun Route.addRoutes() {
        authenticate {
            get("/oauth/confirm_access") { confirmAccess() }
        }
    }
*/

    internal suspend fun RoutingContext.confirmAccess() {
        val authentication = requireRole(GrantedAuthority.ROLE_USER) { return }

        val pendingSession = call.sessions.get<OpenIdSessionStorage>()?.let{
            it.copy(pendingPrompts = Prompt.CONSENT.removeFrom(it.pendingPrompts))
        }
        val authRequest: AuthorizationRequest = pendingSession?.authorizationRequest
            ?: return call.respond(HttpStatusCode.BadRequest)

        // Check the "prompt" parameter to see if we need to do special processing
        val prompts = pendingSession.pendingPrompts ?: emptySet()

        val client: OAuthClientDetails
        try {
            client = clientDetailsService.loadClientByClientId(authRequest.clientId)
                ?: run {
                    logger.error("confirmAccess: could not find client ${authRequest.clientId}")
                    return call.respond(HttpStatusCode.NotFound)
                }
        } catch (e: OAuth2Exception) {
            logger.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e)
            return call.respond(HttpStatusCode.BadRequest)
        } catch (e: IllegalArgumentException) {
            logger.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e)
            return call.respond(HttpStatusCode.BadRequest)
        }

        call.sessions.set(pendingSession)
        try {
            confirmAccess(authentication, authRequest, prompts, client, authRequest.redirectUri)
        } catch (e: Exception) {
            call.sessions.clear<OpenIdSessionStorage>()
            throw e
        }
    }

    internal suspend fun RoutingContext.confirmAccess(
        authentication: Authentication,
        authRequest: AuthorizationRequest,
        prompts: Set<Prompt>,
        client: OAuthClientDetails,
        redirect_uri: String?,
    ) {

        check(arrayOf(Prompt.NONE, Prompt.LOGIN, Prompt.SELECT_ACCOUNT).none { it in prompts }) {
            "Confirmation is always after login"
        }

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
                for (claim in claims) {
                    (userJson[claim] as? JsonPrimitive)?.let {
                        // TODO: this skips the address claim
                        claimValues[claim] = it.toString()
                    }
                }

                claimsForScopes[scopeValue] = claimValues
            }
        }

        // client stats
        val count = statsService.getCountForClientId(client.clientId)?.approvedSiteCount ?: 0

        // if the client is over a week old and has more than one registration, don't give such a big warning
        // instead, tag as "Generally Recognized As Safe" (gras)
        val lastWeek = Instant.now().minus(7, ChronoUnit.DAYS) // use 7 days as weeks is not supported
        val createdAt = client.createdAt
        val gras = count > 1 && createdAt != null && createdAt.toInstant().isBefore(lastWeek)


        htmlApproveView(
            authRequest = authRequest,
            client = client,
            redirectUri = redirect_uri,
            scopes = sortedScopes,
            claims = claimsForScopes,
            approvedSiteCount = count,
            isGras = gras,
            contacts = client.contacts?.joinToString(),
        )
    }

    private val logger = getLogger()
}
