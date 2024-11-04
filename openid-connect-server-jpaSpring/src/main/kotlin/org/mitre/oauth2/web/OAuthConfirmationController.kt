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

import kotlinx.serialization.json.JsonPrimitive
import org.apache.http.client.utils.URIBuilder
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.ScopeClaimTranslationService
import org.mitre.openid.connect.service.StatsService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.SessionAttributes
import java.net.URISyntaxException
import java.security.Principal
import java.time.Instant
import java.time.temporal.ChronoUnit
import org.springframework.security.oauth2.provider.ClientDetails as SpringClientDetails

/**
 * @author jricher
 */
@Controller
@SessionAttributes("authorizationRequest")
class OAuthConfirmationController {
    @Autowired
    lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Autowired
    private lateinit var scopeClaimTranslationService: ScopeClaimTranslationService

    @Autowired
    private lateinit var userInfoService: UserInfoService

    @Autowired
    private lateinit var statsService: StatsService

    @Autowired
    private lateinit var redirectResolver: RedirectResolver

    constructor()

    constructor(clientService: ClientDetailsEntityService) {
        this.clientService = clientService
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping("/oauth/confirm_access")
    fun confirmAccess(model: MutableMap<String?, Any?>, p: Principal): String {
        val authRequest = model["authorizationRequest"] as AuthorizationRequest?

        // Check the "prompt" parameter to see if we need to do special processing
        val prompt = authRequest!!.extensions[ConnectRequestParameters.PROMPT] as String?
        val prompts = prompt?.split(ConnectRequestParameters.PROMPT_SEPARATOR)?: emptyList()
        var client: OAuthClientDetails? = null

        try {
            client = clientService.loadClientByClientId(authRequest.clientId)
        } catch (e: OAuth2Exception) {
            logger.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e)
            model[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            return HttpCodeView.VIEWNAME
        } catch (e: IllegalArgumentException) {
            logger.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e)
            model[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            return HttpCodeView.VIEWNAME
        }

        if (client == null) {
            logger.error("confirmAccess: could not find client " + authRequest.clientId)
            model[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            return HttpCodeView.VIEWNAME
        }

        if (prompts.contains("none")) {
            // if we've got a redirect URI then we'll send it
            // TODO no longer use spring, remove cast
            val url = redirectResolver.resolveRedirect(authRequest.redirectUri, client as SpringClientDetails)

            try {
                val uriBuilder = URIBuilder(url)

                uriBuilder.addParameter("error", "interaction_required")
                if (!authRequest.state.isNullOrEmpty()) {
                    uriBuilder.addParameter("state", authRequest.state) // copy the state parameter if one was given
                }

                return "redirect:$uriBuilder"
            } catch (e: URISyntaxException) {
                logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                model["code"] = HttpStatus.FORBIDDEN
                return HttpCodeView.VIEWNAME
            }
        }

        model["auth_request"] = authRequest
        model["client"] = client

        val redirect_uri = authRequest.redirectUri

        model["redirect_uri"] = redirect_uri


        // pre-process the scopes
        val scopes: Set<SystemScope?>? = scopeService.fromStrings(authRequest.scope)

        val sortedScopes: MutableSet<SystemScope?> = LinkedHashSet(scopes!!.size)
        val systemScopes: Set<SystemScope?> = scopeService.all

        // sort scopes for display based on the inherent order of system scopes
        for (s in systemScopes) {
            if (scopes.contains(s)) {
                sortedScopes.add(s)
            }
        }

        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(scopes - systemScopes)

        model["scopes"] = sortedScopes

        // get the userinfo claims for each scope
        val user = userInfoService.getByUsername(p.name)
        val claimsForScopes: MutableMap<String?, Map<String, String>> = HashMap()
        if (user != null) {
            val userJson = user.toJson()

            for (systemScope in sortedScopes) {
                val claimValues: MutableMap<String, String> = HashMap()
                val scopeValue = systemScope!!.value!!

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

        model["claims"] = claimsForScopes

        // client stats
        val count = statsService.getCountForClientId(client.clientId)!!.approvedSiteCount ?: 0
        model["count"] = count


        // contacts
        if (client.contacts != null) {
            val contacts = client.contacts?.joinToString(", ")
            model["contacts"] = contacts
        }

        // if the client is over a week old and has more than one registration, don't give such a big warning
        // instead, tag as "Generally Recognized As Safe" (gras)
        val lastWeek = Instant.now().minus(1, ChronoUnit.WEEKS)
        val createdAt = client.createdAt
        model["gras"] = count > 1 && createdAt != null && createdAt.toInstant().isBefore(lastWeek)

        return "approve"
    }


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<OAuthConfirmationController>()
    }
}
