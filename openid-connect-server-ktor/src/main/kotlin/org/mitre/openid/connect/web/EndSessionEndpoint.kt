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
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.util.getLogger
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.htmlLogoutConfirmationView
import org.mitre.web.htmlPostLogoutView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.assertionValidator
import org.mitre.web.util.clientService
import org.mitre.web.util.resolveAuthenticatedUser
import org.mitre.web.util.update
import org.mitre.web.util.userInfoService
import java.text.ParseException

/**
 * Implementation of the End Session Endpoint from OIDC session management
 *
 * @author jricher
 */
object EndSessionEndpoint: KtorEndpoint {
//    private lateinit var validator: SelfAssertionValidator

//    private lateinit var userInfoService: UserInfoService

//    private lateinit var clientService: ClientDetailsEntityService

    override fun Route.addRoutes() {
        authenticate {
            get("/endsession") { endSession() }
            post("/endsession") { processLogout() }
        }
    }

//    @RequestMapping(value = ["/" + URL], method = [RequestMethod.GET])
    suspend fun PipelineContext<Unit, ApplicationCall>.endSession() {
        val auth = resolveAuthenticatedUser()

        val state: String? = call.request.queryParameters["state"]
        val idTokenHint: String? = call.request.queryParameters["id_token_hint"]
        val postLogoutRedirectUri: String? = call.request.queryParameters["post_logout_redirect_uri"]

        // conditionally filled variables

        var idTokenClaims: JWTClaimsSet? = null // pulled from the parsed and validated ID token
        var client: OAuthClientDetails? = null // pulled from ID token's audience field

        if (!postLogoutRedirectUri.isNullOrEmpty()) {
            call.sessions.update<OpenIdSessionStorage> { it?.copy(redirectUri = postLogoutRedirectUri) ?: OpenIdSessionStorage(redirectUri = postLogoutRedirectUri) }
        }
        if (!state.isNullOrEmpty()) {
            call.sessions.update<OpenIdSessionStorage> { it?.copy(state = state) ?: OpenIdSessionStorage(state = state) }
        }


        // parse the ID token hint to see if it's valid
        if (!idTokenHint.isNullOrEmpty()) {
            try {
                val idToken = JWTParser.parse(idTokenHint)

                if (assertionValidator.isValid(idToken)) {
                    // we issued this ID token, figure out who it's for
                    idTokenClaims = idToken.jwtClaimsSet

                    val clientId = idTokenClaims.audience.single()

                    client = clientService.loadClientByClientId(clientId)


                    // save a reference in the session for us to pick up later
                    //session.setAttribute("endSession_idTokenHint_claims", idTokenClaims);

                    TODO("Evaluate setting the client in the session")
//                    session.setAttribute(CLIENT_KEY, client)
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
        if (auth == null || GrantedAuthority.ROLE_USER !in auth.authorities) {
            // we're not logged in anyway, process the final redirect bits if needed
            return processLogout(null, client)
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

            // display the log out confirmation page
            return htmlLogoutConfirmationView(client/*, idTokenClaims*/)
        }
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.processLogout() {
        val clientId = call.receiveParameters()["clientId"]
        val client: OAuthClientDetails? = clientId?.let { clientService.loadClientByClientId(it) }
        processLogout(call.request.queryParameters["approved"], client)
    }

//    @RequestMapping(value = ["/" + URL], method = [RequestMethod.POST])
    private suspend fun PipelineContext<Unit, ApplicationCall>.processLogout(
        approved: String?,
        client: OAuthClientDetails?
    ) {
        val auth = resolveAuthenticatedUser()

        val oidSession = call.sessions.get<OpenIdSessionStorage>()
        val redirectUri = oidSession?.redirectUri
        val state = oidSession?.state
        //val client: String? = TODO("oidSession?.clientKey")

        if (!approved.isNullOrEmpty()) {
            // use approved, perform the logout
            if (auth != null) {
                TODO("""invalidate the tokens
                  SecurityContextLogoutHandler().logout(request, response, auth)
                """)
            }
            call.sessions.set<OpenIdSessionStorage>(null) // reset the session
            // TODO: hook into other logout post-processing
        }


        // if the user didn't approve, don't log out but hit the landing page anyway for redirect as needed


        // if we have a client AND the client has post-logout redirect URIs
        // registered AND the URI given is in that list, then...
        if (!redirectUri.isNullOrEmpty() && client != null && client.postLogoutRedirectUris != null) {
            if (client.postLogoutRedirectUris!!.contains(redirectUri)) {
                // TODO: future, add the redirect URI to the model for the display page for an interstitial
                // m.addAttribute("redirectUri", postLogoutRedirectUri);

                val uri = URLBuilder(redirectUri).apply { state?.let { parameters["state"] = it } }.build()

                call.respondRedirect(uri)
            }
        }

        // otherwise, return to a nice post-logout landing page
        return htmlPostLogoutView()
    }

    const val URL: String = "endsession"

    private const val CLIENT_KEY = "client"
    private const val STATE_KEY = "state"
    private const val REDIRECT_URI_KEY = "redirectUri"

    private val logger = getLogger()
}
