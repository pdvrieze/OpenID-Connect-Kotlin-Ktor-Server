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
import kotlinx.serialization.json.JsonPrimitive
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.uma.model.Claim
import org.mitre.uma.service.PermissionService
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam

/**
 *
 * Collect claims interactively from the end user.
 *
 * @author jricher
 */
@Controller
@PreAuthorize("hasRole('ROLE_EXTERNAL_USER')")
@RequestMapping("/" + ClaimsCollectionEndpoint.URL)
class ClaimsCollectionEndpoint {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var permissionService: PermissionService


    @RequestMapping(method = [RequestMethod.GET])
    fun collectClaims(
        @RequestParam("client_id") clientId: String,
        @RequestParam(value = "redirect_uri", required = false) redirectUri: String,
        @RequestParam("ticket") ticketValue: String,
        @RequestParam(value = "state", required = false) state: String?,
        m: Model,
        auth: OIDCAuthenticationToken
    ): String {
        var redirectUri = redirectUri
        val client = clientService.loadClientByClientId(clientId)

        val ticket = permissionService.getByTicket(ticketValue)

        if (client == null || ticket == null) {
            logger.info("Client or ticket not found: $clientId :: $ticketValue")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        // we've got a client and ticket, let's attach the claims that we have from the token and userinfo

        // subject
        val claimsSupplied: MutableSet<Claim> = ticket.claimsSupplied?.toHashSet() ?: hashSetOf()

        val issuer = auth.issuer
        val userInfo = auth.userInfo!!

        claimsSupplied.add(
            Claim(
                name = "sub",
                value = JsonPrimitive(auth.sub),
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
                    value = JsonPrimitive(auth.userInfo!!.phoneNumber),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.phoneNumberVerified != null) {
            claimsSupplied.add(
                Claim(
                    name = "phone_number_verified",
                    value = JsonPrimitive(auth.userInfo!!.phoneNumberVerified),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.preferredUsername != null) {
            claimsSupplied.add(
                Claim(
                    name = "preferred_username",
                    value = JsonPrimitive(auth.userInfo!!.preferredUsername),
                    issuer = hashSetOf(issuer),
                )
            )
        }
        if (userInfo.profile != null) {
            claimsSupplied.add(
                Claim(
                    name = "profile",
                    value = JsonPrimitive(auth.userInfo!!.profile),
                    issuer = hashSetOf(issuer),
                )
            )
        }

        val updatedTicket = permissionService.updateTicket(ticket.copy(claimsSupplied = claimsSupplied))

        if (redirectUri.isNullOrEmpty()) {
            if (client.claimsRedirectUris!!.size == 1) {
                redirectUri =
                    client.claimsRedirectUris!!.iterator().next() // get the first (and only) redirect URI to use here
                logger.info("No redirect URI passed in, using registered value: $redirectUri")
            } else {
                throw RedirectMismatchException("Unable to find redirect URI and none passed in.")
            }
        } else {
            if (!client.claimsRedirectUris!!.contains(redirectUri)) {
                throw RedirectMismatchException("Claims redirect did not match the registered values.")
            }
        }

        val template = URLBuilder(redirectUri)

        template.parameters.append("authorization_state", "claims_submitted")
        if (!state.isNullOrEmpty()) {
            template.parameters.append("state", state)
        }

        val uriString = template.buildString()
        logger.info("Redirecting to $uriString")

        return "redirect:$uriString"
    }


    companion object {
        // Logger for this class
        private val logger = getLogger<ClaimsCollectionEndpoint>()

        const val URL: String = "rqp_claims"
    }
}
