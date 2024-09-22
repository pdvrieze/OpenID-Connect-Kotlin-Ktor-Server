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
package org.mitre.openid.connect.web

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import org.mitre.jwt.assertion.impl.SelfAssertionValidator
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.service.UserInfoService
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.util.UriComponentsBuilder
import java.text.ParseException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

/**
 * Implementation of the End Session Endpoint from OIDC session management
 *
 * @author jricher
 */
@Controller
class EndSessionEndpoint {
    @Autowired
    private lateinit var validator: SelfAssertionValidator

    @Autowired
    private lateinit var userInfoService: UserInfoService

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @RequestMapping(value = ["/" + URL], method = [RequestMethod.GET])
    fun endSession(
        @RequestParam(value = "id_token_hint", required = false) idTokenHint: String?,
        @RequestParam(value = "post_logout_redirect_uri", required = false) postLogoutRedirectUri: String?,
        @RequestParam(value = STATE_KEY, required = false) state: String?,
        request: HttpServletRequest,
        response: HttpServletResponse?,
        session: HttpSession,
        auth: Authentication?, m: Model
    ): String {
        // conditionally filled variables

        var idTokenClaims: JWTClaimsSet? = null // pulled from the parsed and validated ID token
        var client: OAuthClientDetails? = null // pulled from ID token's audience field

        if (!postLogoutRedirectUri.isNullOrEmpty()) {
            session.setAttribute(REDIRECT_URI_KEY, postLogoutRedirectUri)
        }
        if (!state.isNullOrEmpty()) {
            session.setAttribute(STATE_KEY, state)
        }


        // parse the ID token hint to see if it's valid
        if (!idTokenHint.isNullOrEmpty()) {
            try {
                val idToken = JWTParser.parse(idTokenHint)

                if (validator.isValid(idToken)) {
                    // we issued this ID token, figure out who it's for
                    idTokenClaims = idToken.jwtClaimsSet

                    val clientId = idTokenClaims.audience.single()

                    client = clientService.loadClientByClientId(clientId)


                    // save a reference in the session for us to pick up later
                    //session.setAttribute("endSession_idTokenHint_claims", idTokenClaims);
                    session.setAttribute(CLIENT_KEY, client)
                }
            } catch (e: ParseException) {
                // it's not a valid ID token, ignore it
                logger.debug("Invalid id token hint", e)
            } catch (e: InvalidClientException) {
                // couldn't find the client, ignore it
                logger.debug("Invalid client", e)
            }
        }


        // are we logged in or not?
        if (auth == null || !request.isUserInRole("ROLE_USER")) {
            // we're not logged in anyway, process the final redirect bits if needed
            return processLogout(null, request, response, session, auth, m)
        } else {
            // we are logged in, need to prompt the user before we log out

            // see who the current user is

            val ui = userInfoService.getByUsername(auth.name)

            if (idTokenClaims != null) {
                val subject = idTokenClaims.subject
                // see if the current user is the same as the one in the ID token
                // TODO: should we do anything different in these cases?
                if (!subject.isNullOrEmpty() && subject == ui!!.subject) {
                    // it's the same user
                } else {
                    // it's not the same user
                }
            }

            m.addAttribute("client", client)
            m.addAttribute("idToken", idTokenClaims)


            // display the log out confirmation page
            return "logoutConfirmation"
        }
    }

    @RequestMapping(value = ["/" + URL], method = [RequestMethod.POST])
    fun processLogout(
        @RequestParam(value = "approve", required = false) approved: String?,
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        session: HttpSession,
        auth: Authentication?, m: Model?
    ): String {
        val redirectUri = session.getAttribute(REDIRECT_URI_KEY) as String
        val state = session.getAttribute(STATE_KEY) as String
        val client = session.getAttribute(CLIENT_KEY) as ClientDetailsEntity?

        if (!approved.isNullOrEmpty()) {
            // use approved, perform the logout
            if (auth != null) {
                SecurityContextLogoutHandler().logout(request, response, auth)
            }
            SecurityContextHolder.getContext().authentication = null
            // TODO: hook into other logout post-processing
        }


        // if the user didn't approve, don't log out but hit the landing page anyway for redirect as needed


        // if we have a client AND the client has post-logout redirect URIs
        // registered AND the URI given is in that list, then...
        if (!redirectUri.isNullOrEmpty() && client != null && client.postLogoutRedirectUris != null) {
            if (client.postLogoutRedirectUris!!.contains(redirectUri)) {
                // TODO: future, add the redirect URI to the model for the display page for an interstitial
                // m.addAttribute("redirectUri", postLogoutRedirectUri);

                val uri = UriComponentsBuilder.fromHttpUrl(redirectUri).queryParam("state", state).build()

                return "redirect:$uri"
            }
        }


        // otherwise, return to a nice post-logout landing page
        return "postLogout"
    }

    companion object {
        const val URL: String = "endsession"

        private const val CLIENT_KEY = "client"
        private const val STATE_KEY = "state"
        private const val REDIRECT_URI_KEY = "redirectUri"

        private val logger = getLogger<EndSessionEndpoint>()
    }
}
