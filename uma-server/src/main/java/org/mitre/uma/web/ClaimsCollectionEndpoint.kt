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

import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.uma.model.Claim
import org.mitre.uma.service.PermissionService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.util.UriComponentsBuilder

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

        claimsSupplied.add(mkClaim(issuer, "sub", JsonPrimitive(auth.sub)))
        if (userInfo.email != null) {
            claimsSupplied.add(mkClaim(issuer, "email", JsonPrimitive(userInfo.email)))
        }
        if (userInfo.emailVerified != null) {
            claimsSupplied.add(mkClaim(issuer, "email_verified", JsonPrimitive(userInfo.emailVerified)))
        }
        if (userInfo.phoneNumber != null) {
            claimsSupplied.add(mkClaim(issuer, "phone_number", JsonPrimitive(auth.userInfo!!.phoneNumber)))
        }
        if (userInfo.phoneNumberVerified != null) {
            claimsSupplied.add(mkClaim(issuer, "phone_number_verified", JsonPrimitive(auth.userInfo!!.phoneNumberVerified)))
        }
        if (userInfo.preferredUsername != null) {
            claimsSupplied.add(mkClaim(issuer, "preferred_username", JsonPrimitive(auth.userInfo!!.preferredUsername)))
        }
        if (userInfo.profile != null) {
            claimsSupplied.add(mkClaim(issuer, "profile", JsonPrimitive(auth.userInfo!!.profile)))
        }

        ticket.claimsSupplied = claimsSupplied

        val updatedTicket = permissionService.updateTicket(ticket)

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

        val template = UriComponentsBuilder.fromUriString(redirectUri)
        template.queryParam("authorization_state", "claims_submitted")
        if (!state.isNullOrEmpty()) {
            template.queryParam("state", state)
        }

        val uriString = template.toUriString()
        logger.info("Redirecting to $uriString")

        return "redirect:$uriString"
    }


    private fun mkClaim(issuer: String, name: String, value: JsonElement): Claim {
        val c = Claim()
        c.issuer = hashSetOf(issuer)
        c.name = name
        c.value = value
        return c
    }

    companion object {
        // Logger for this class
        private val logger: Logger = LoggerFactory.getLogger(ClaimsCollectionEndpoint::class.java)

        const val URL: String = "rqp_claims"
    }
}
