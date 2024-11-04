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
package org.mitre.uma.web

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.service.RedirectResolver
import org.mitre.openid.connect.model.DefaultUserInfo
import org.mitre.uma.model.Claim
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.permissionService
import org.mitre.web.util.requireRole

/**
 *
 * Collect claims interactively from the end user.
 *
 * @author jricher
 */
//@PreAuthorize("hasRole('ROLE_EXTERNAL_USER')")
object ClaimsCollectionEndpoint : KtorEndpoint {
    override fun Route.addRoutes() {
        route("/rqp_claims") {
            authenticate {
                get { collectClaims()}
            }

        }
    }

    private suspend fun RoutingContext.collectClaims() {
        val auth = requireRole(GrantedAuthority.ROLE_EXTERNAL_USER) { return }
        val clientId = call.request.queryParameters["client_id"] ?: return call.respond(HttpStatusCode.BadRequest)
        var redirectUri = call.request.queryParameters["redirect_uri"]
        val ticketValue = call.request.queryParameters["ticket"] ?: return call.respond(HttpStatusCode.BadRequest)
        val state = call.request.queryParameters["state"]

        if (auth !is OAuth2AccessToken) return call.respond(HttpStatusCode.Unauthorized) // requires OAuth

        val client = clientDetailsService.loadClientByClientId(clientId)

        val ticket = permissionService.getByTicket(ticketValue)

        if (client == null || ticket == null) {
            logger.info("Client or ticket not found: $clientId :: $ticketValue")
            return call.respond(HttpStatusCode.NotFound)
        }

        // we've got a client and ticket, let's attach the claims that we have from the token and userinfo

        // subject
        val claimsSupplied: MutableSet<Claim> = ticket.claimsSupplied?.toHashSet() ?: hashSetOf()

        val issuer = auth.issuer
        // TODO actually look up user information, either from OpenIdConnect or the userInfoService.
        val userInfo = DefaultUserInfo(auth.name)//auth.jwt.jwtClaimsSet.userInfo!!

        claimsSupplied.add(
            Claim(
                name = "sub",
                value = JsonPrimitive(auth.name),
                issuer = hashSetOf(issuer),
            )
        )
        if (userInfo.email != null) {
            claimsSupplied.add(
                Claim(
                    name = "email",
                    value = JsonPrimitive(userInfo.email),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.emailVerified != null) {
            claimsSupplied.add(
                Claim(
                    name = "email_verified",
                    value = JsonPrimitive(userInfo.emailVerified),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.phoneNumber != null) {
            claimsSupplied.add(
                Claim(
                    name = "phone_number",
                    value = JsonPrimitive(userInfo.phoneNumber),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.phoneNumberVerified != null) {
            claimsSupplied.add(
                Claim(
                    name = "phone_number_verified",
                    value = JsonPrimitive(userInfo.phoneNumberVerified),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.preferredUsername != null) {
            claimsSupplied.add(
                Claim(
                    name = "preferred_username",
                    value = JsonPrimitive(userInfo.preferredUsername),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.profile != null) {
            claimsSupplied.add(
                Claim(
                    name = "profile",
                    value = JsonPrimitive(userInfo.profile),
                    issuer = hashSetOf(issuer),
                )
            )
        }

        val updatedTicket = permissionService.updateTicket(ticket.copy(claimsSupplied = claimsSupplied))

        if (redirectUri.isNullOrEmpty()) {
            if (client.claimsRedirectUris?.size == 1) {
                redirectUri =
                    client.claimsRedirectUris!!.iterator().next() // get the first (and only) redirect URI to use here
                logger.info("No redirect URI passed in, using registered value: $redirectUri")
            } else {
                throw RedirectResolver.RedirectMismatchException("Unable to find redirect URI and none passed in.")
            }
        } else {
            if (!client.claimsRedirectUris!!.contains(redirectUri)) {
                throw RedirectResolver.RedirectMismatchException("Claims redirect did not match the registered values.")
            }
        }

        val template = URLBuilder(redirectUri)

        template.parameters.append("authorization_state", "claims_submitted")
        if (!state.isNullOrEmpty()) {
            template.parameters.append("state", state)
        }

        val uriString = template.buildString()
        logger.info("Redirecting to $uriString")

        return call.respondRedirect(uriString)
    }


    // Logger for this class
    private val logger = getLogger<ClaimsCollectionEndpoint>()

    const val URL: String = "rqp_claims"
}
