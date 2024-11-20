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
package org.mitre.oauth2.web

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.exception.DeviceCodeCreationException
import org.mitre.oauth2.exception.InvalidClientException
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.token.DeviceTokenGranter
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.htmlApproveDeviceView
import org.mitre.web.htmlRequestUserCodeView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.deviceCodeService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import org.mitre.web.util.scopeService
import java.net.URISyntaxException
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 * Implements https://tools.ietf.org/html/draft-ietf-oauth-device-flow
 *
 * @see DeviceTokenGranter
 *
 *
 * @author jricher
 */
object DeviceEndpoint : KtorEndpoint {

    override fun Route.addRoutes() {
        post("/devicecode") {
            requestDeviceCode()
        }
        authenticate {
            get("/device") {
                requestUserCode()
            }
            post("/device/verify") {
                readUserCode()
            }
            post("/device/approve") {
                approveDevice()
            }
        }
    }

    private suspend fun RoutingContext.requestDeviceCode() {
        val config = openIdContext.config
        require(call.request.contentType().withoutParameters() == ContentType.Application.FormUrlEncoded) {
            "Only Form url-encoded is supported (was: ${call.request.contentType()})"
        }
        val parameters = call.receiveParameters()
        val clientId = parameters["client_id"] ?: return call.respond(HttpStatusCode.BadRequest)
        val scope = parameters["scope"]

        val client: OAuthClientDetails
        try {
            client = clientDetailsService.loadClientByClientId(clientId) ?: run {
                logger.error("could not find client $clientId")
                return call.respond(HttpStatusCode.NotFound)
            }

            // make sure this client can do the device flow
            val authorizedGrantTypes = client.authorizedGrantTypes
            if (authorizedGrantTypes.isNotEmpty()
                && DeviceTokenGranter.GRANT_TYPE !in authorizedGrantTypes
            ) {
                throw InvalidClientException("Unauthorized grant type: " + DeviceTokenGranter.GRANT_TYPE)
            }
        } catch (e: IllegalArgumentException) {
            logger.error("IllegalArgumentException was thrown when attempting to load client", e)
            return call.respond(HttpStatusCode.BadRequest)
        }

        // make sure the client is allowed to ask for those scopes
        val requestedScopes = scope
            ?.let { it.splitToSequence(' ').filterTo(HashSet()) { it.isNotEmpty() } }
            ?: emptySet()

        val allowedScopes = client.scope

        if (!scopeService.scopesMatch(allowedScopes, requestedScopes)) {
            // client asked for scopes it can't have
            logger.error("Client asked for $requestedScopes but is allowed $allowedScopes")
            return jsonErrorView("invalid_scope", code = HttpStatusCode.BadRequest)
        }

        // if we got here the request is legit
        try {
            // TODO this looks bonkers and is a big security gap
            val requestParamMap: Map<String, String> =
                parameters.entries().associate { it.key to it.value.joinToString(" ") }

            val validitySeconds = client.deviceCodeValiditySeconds?.let(Duration::ofSeconds) ?: config.defaultDeviceCodeValiditySeconds

            val dc = deviceCodeService.createNewDeviceCode(requestedScopes, client, Instant.now() + validitySeconds, requestParamMap)

            val response = buildJsonObject {
                put("device_code", dc.deviceCode)
                put("user_code", dc.userCode)
                put("verification_uri", "${config.issuer}device")
                put("expires_in", validitySeconds.seconds)

                if (config.isAllowCompleteDeviceCodeUri) {
                    val verificationUriComplete = URLBuilder("${config.issuer}device")
                        .parameters.apply {
                            dc.userCode?.let { uc -> append("user_code", uc) }
                        }
                        .build()

                    put("verification_uri_complete", verificationUriComplete.toString())
                }
            }

            call.respondJson(response)
        } catch (dcce: DeviceCodeCreationException) {
            return jsonErrorView(dcce.error, dcce.message, code = HttpStatusCode.BadRequest)
        } catch (use: URISyntaxException) {
            logger.error("unable to build verification_uri_complete due to wrong syntax of uri components", use)
            return call.respond(HttpStatusCode.InternalServerError)
        }

    }

    private suspend fun RoutingContext.requestUserCode() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }

        val userCode = call.parameters["user_code"]
        if (!openIdContext.config.isAllowCompleteDeviceCodeUri || userCode == null) {
            // if we don't allow the complete URI or we didn't get a user code on the way in,
            // print out a page that asks the user to enter their user code
            // user must be logged in
            // TODO forward to requestUserCode page
            return htmlRequestUserCodeView()
        } else {
            // complete verification uri was used, we received user code directly
            // skip requesting code page
            // user must be logged in

            readUserCodeImpl(userCode, auth)
        }

    }


    private suspend fun RoutingContext.readUserCode() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }

        val userCode = call.receiveParameters()["user_code"]
            ?: return call.respond(HttpStatusCode.BadRequest)

        readUserCodeImpl(userCode, auth)
    }

    private suspend fun RoutingContext.readUserCodeImpl(userCode: String, auth: Authentication) {

        // look up the request based on the user code

        val dc = deviceCodeService.lookUpByUserCode(userCode)
            ?: return doError("noUserCode")

        // make sure the code hasn't expired yet
        if (dc.expiration?.before(Date()) == true) {
            return doError("expiredUserCode")
        }

        // make sure the device code hasn't already been approved
        if (dc.isApproved == true) {
            return doError("userCodeAlreadyApproved")
        }

        val client = clientDetailsService.loadClientByClientId(dc.clientId!!)!!

        // model["client"] = client
        // model["dc"] = dc

        // pre-process the scopes
        val scopes: Set<SystemScope> = scopeService.fromStrings(dc.scope) ?: emptySet()

        val systemScopes: Set<SystemScope> = scopeService.all

        // sort scopes for display based on the inherent order of system scopes
        val sortedScopes = systemScopes.filterTo(HashSet()) { it in scopes }

        systemScopes.filterTo(sortedScopes) { it in scopes }
        // add in any scopes that aren't system scopes to the end of the list
        scopes.filterTo(sortedScopes) { it !in systemScopes }

        val paramTransform: Map<String, List<String>>? = dc.requestParameters?.let { it.mapValues { (_, v) -> listOf(v) } }

//        val p = dc.requestParameters?.let { parametersOf(it.mapValues { (_, v) -> listOf(v) }) }
//        val authorizationRequest = openIdContext.authRequestFactory.createAuthorizationRequest(p ?: parametersOf())
        return htmlApproveDeviceView(
            client = client,
            scopes = sortedScopes,
        )

        //        model["scopes"] = sortedScopes

        TODO("Handle createAuthorizationRequest")
        //        val authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(dc.requestParameters)
        //
        //        session.setAttribute("authorizationRequest", authorizationRequest)
        //        session.setAttribute("deviceCode", dc)
        //
        //
        //
        //        return "approveDevice"

    }

    private suspend fun RoutingContext.approveDevice() {
            val userCode: String = call.request.queryParameters["user_code"]
                ?: call.receiveParameters()["user_code"]
                ?: return call.respond(HttpStatusCode.BadRequest)

            val approve = call.request.queryParameters["user_oauth_approval"]
                ?: call.receiveParameters()["user_oauth_approval"]



            TODO("Implement this")

            /*
            val authorizationRequest = session.getAttribute("authorizationRequest") as AuthorizationRequest
            val dc = session.getAttribute("deviceCode") as DeviceCode

            // make sure the form that was submitted is the one that we were expecting
            if (dc.userCode != userCode) {
                model.addAttribute("error", "userCodeMismatch")
                return "requestUserCode"
            }

            // make sure the code hasn't expired yet
            if (dc.expiration != null && dc.expiration!!.before(Date())) {
                model.addAttribute("error", "expiredUserCode")
                return "requestUserCode"
            }

            val client = clientService.loadClientByClientId(dc.clientId!!)

            model["client"] = client

            // user did not approve
            if (!approve!!) {
                model.addAttribute("approved", false)
                return "deviceApproved"
            }

            // create an OAuth request for storage
            val o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest).fromSpring()
            val o2Auth = OAuth2Authentication(o2req, auth?.fromSpring())

            val approvedCode = deviceCodeService.approveDeviceCode(dc, o2Auth)


            // pre-process the scopes
            val scopes: Set<SystemScope> = scopeService.fromStrings(dc.scope!!)?: emptySet()

            val sortedScopes: MutableSet<SystemScope> = LinkedHashSet(scopes.size)
            val systemScopes: Set<SystemScope> = scopeService.all

            // sort scopes for display based on the inherent order of system scopes
            for (s in systemScopes) {
                if (scopes.contains(s)) {
                    sortedScopes.add(s)
                }
            }

            // add in any scopes that aren't system scopes to the end of the list
            sortedScopes.addAll(Sets.difference(scopes, systemScopes))

            model["scopes"] = sortedScopes
            model["approved"] = true

            return "deviceApproved"
*/



    }

    // TODO for errors create a mapping form requestUserCode.jsp (use enums?)
    suspend fun RoutingContext.doError(category: String) {
        call.respond(HttpStatusCode.BadRequest, category)
    }

    const val URL: String = "devicecode"
    const val USER_URL: String = "device"

    val logger = getLogger<DeviceEndpoint>()
}

