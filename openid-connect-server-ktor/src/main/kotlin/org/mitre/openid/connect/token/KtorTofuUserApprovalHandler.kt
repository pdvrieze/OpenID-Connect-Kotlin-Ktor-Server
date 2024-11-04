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
package org.mitre.openid.connect.token

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.convert.AuthorizationRequest
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 * Custom User Approval Handler implementation which uses a concept of a whitelist,
 * blacklist, and greylist.
 *
 * Blacklisted sites will be caught and handled before this
 * point.
 *
 * Whitelisted sites will be automatically approved, and an ApprovedSite entry will
 * be created for the site the first time a given user access it.
 *
 * All other sites fall into the greylist - the user will be presented with the user
 * approval page upon their first visit
 * @author aanganes
 */
class KtorTofuUserApprovalHandler(
    val approvedSiteService: ApprovedSiteService,
    val whitelistedSiteService: WhitelistedSiteService,
    val clientDetailsService: ClientDetailsEntityService,
    val systemScopes: SystemScopeService,
) : UserApprovalHandler {

    /**
     * Check if the user has already stored a positive approval decision for this site; or if the
     * site is whitelisted, approve it automatically.
     *
     * Otherwise, return false so that the user will see the approval page and can make their own decision.
     *
     * @param authorizationRequest    the incoming authorization request
     * @param userAuthentication    the Principal representing the currently-logged-in user
     *
     * @return                        true if the site is approved, false otherwise
     */
    override fun isApproved(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        postParams: Map<String, String>
    ): Boolean {
        // if this request is already approved, pass that info through
        // (this flag may be set by updateBeforeApproval, which can also do funny things with scopes, etc)

        return if (authorizationRequest.isApproved) {
            true
        } else {
            // if not, check to see if the user has approved it
            // TODO: make parameter name configurable?
            postParams["user_oauth_approval"] == "true" && postParams["authorize"] == "Authorize"
        }
    }

    /**
     * Check if the user has already stored a positive approval decision for this site; or if the
     * site is whitelisted, approve it automatically.
     *
     * Otherwise the user will be directed to the approval page and can make their own decision.
     *
     * @param authorizationRequest    the incoming authorization request
     * @param userAuthentication    the Principal representing the currently-logged-in user
     *
     * @return                        the updated AuthorizationRequest
     */
    override fun checkForPreApproval(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        prompts: Set<String>?
    ): AuthorizationRequest {
        //First, check database to see if the user identified by the userAuthentication has stored an approval decision
        var newApproved = authorizationRequest.isApproved
        val newExtensions: MutableMap<String, String> = HashMap<String, String>(authorizationRequest.extensions)

        val userId = userAuthentication.name
        val clientId = authorizationRequest.clientId

        //lookup ApprovedSites by userId and clientId
        var alreadyApproved = false

        if (prompts == null || ConnectRequestParameters.PROMPT_CONSENT !in prompts) {
            // if the prompt parameter is set to "consent" then we can't use approved sites or whitelisted sites
            // otherwise, we need to check them below

            val aps = checkNotNull(approvedSiteService.getByClientIdAndUserId(clientId, userId)) {
                "Missing approved site service for client:$clientId and user:$userId"
            }
            for (ap in aps) {
                if (!ap.isExpired) {
                    // if we find one that fits...

                    if (systemScopes.scopesMatch(ap.allowedScopes, authorizationRequest.scope)) {
                        //We have a match; update the access date on the AP entry and return true.

                        ap.accessDate = Instant.now()
                        approvedSiteService.save(ap)

                        val apId = ap.id.toString()
                        newExtensions[ConnectRequestParameters.APPROVED_SITE] = apId

                        newApproved = true
                        alreadyApproved = true

                        setAuthTime(newExtensions)
                    }
                }
            }

            if (!alreadyApproved) {
                val ws = whitelistedSiteService.getByClientId(clientId)
                if (ws != null && systemScopes.scopesMatch(ws.allowedScopes, authorizationRequest.scope)) {
                    newApproved = true

                    setAuthTime(newExtensions)
                }
            }
        }


        return authorizationRequest.copy(isApproved = newApproved, extensionStrings = newExtensions.takeIf { it.isNotEmpty() })
    }


    override fun updateAfterApproval(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        postParams: Map<String, String>
    ): AuthorizationRequest {
        val userId = userAuthentication.name
        val clientId = authorizationRequest.clientId
        val client = clientDetailsService.loadClientByClientId(clientId)!!
        var newApproved = authorizationRequest.isApproved
        var newScope = authorizationRequest.scope
        val newExtensions = HashMap<String, String>(authorizationRequest.extensions)

        val newApprovalParameters = when(val oldApprovalParameters = postParams) {
            null -> null

            else -> buildJsonObject {
                // This must be re-parsed here because SECOAUTH forces us to call things in a strange order
                if (oldApprovalParameters["user_oauth_approval"] == "true") {
                    newApproved = true

                    //This is a scope parameter from the approval page. The value sent back should
                    //be the scope string. Check to make sure it is contained in the client's
                    //registered allowed scopes.
                    val allowedScopes = oldApprovalParameters.asSequence()
                        .filter { it.key.startsWith("scope_")  }
                        .map { setOf(it.value) }
                        //Make sure this scope is allowed for the given client
                        .filter { scopes -> systemScopes.scopesMatch(client.scope, scopes) }
                        .flatMapTo(HashSet()) { it }

                    // inject the user-allowed scopes into the auth request
                    newScope = allowedScopes

                    //Only store an ApprovedSite if the user has checked "remember this decision":
                    when(postParams["remember"]) {
                        "one-hour" -> {
                            val timeout: Date? = Date.from(Instant.now()+Duration.ofHours(1))

                            val newSite = approvedSiteService.createApprovedSite(clientId, userId, timeout, allowedScopes)
                            val newSiteId = newSite.id.toString()
                            put(ConnectRequestParameters.APPROVED_SITE, newSiteId)

                        }
                        "until-revoked" -> {
                            val newSite = approvedSiteService.createApprovedSite(clientId, userId, null as Date?, allowedScopes)
                            val newSiteId = newSite.id.toString()
                            put(ConnectRequestParameters.APPROVED_SITE, newSiteId)
                        }
                        else -> { // default to not remembering

                        }
                    }
                    val remember = oldApprovalParameters["remember"]
                    if (!remember.isNullOrEmpty() && remember != "none") {
                        var timeout: Date? = null
                        if (remember == "one-hour") {
                            // set the timeout to one hour from now
                            timeout = Date.from(Instant.now()+Duration.ofHours(1))
                        }

                        val newSite = approvedSiteService.createApprovedSite(clientId, userId, timeout, allowedScopes)
                        val newSiteId = newSite.id.toString()
                        put(ConnectRequestParameters.APPROVED_SITE, newSiteId)
                    }

                    setAuthTime(newExtensions)
                }
            }

        }



        return authorizationRequest.copy(
            isApproved = newApproved,
            scope = newScope,
            extensionStrings = newExtensions.takeIf { it.isNotEmpty() },
        )
    }

    /**
     * Get the auth time out of the current session and add it to the
     * auth request in the extensions map.
     *
     */
    private fun setAuthTime(extensions: MutableMap<String, String>) {
        // Get the session auth time, if we have it, and store it in the request
        extensions[AuthenticationTimeStamper.AUTH_TIMESTAMP] =Date().time.toString()
    }

    fun getUserApprovalRequest(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication
    ): Map<String, Any> {
        val model: MutableMap<String, Any> = HashMap()
        // In case of a redirect we might want the request parameters to be included
        model.putAll(authorizationRequest.requestParameters)
        return model
    }
}
