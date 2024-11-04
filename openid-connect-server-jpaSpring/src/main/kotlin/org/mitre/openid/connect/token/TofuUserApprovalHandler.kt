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

import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.request.Prompt
import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetailsService
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler
import org.springframework.stereotype.Component
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
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
@Component("tofuUserApprovalHandler")
class TofuUserApprovalHandler : UserApprovalHandler {
    @Autowired
    private lateinit var approvedSiteService: ApprovedSiteService

    @Autowired
    private lateinit var whitelistedSiteService: WhitelistedSiteService

    @Autowired
    private lateinit var clientDetailsService: ClientDetailsService

    @Autowired
    private lateinit var systemScopes: SystemScopeService

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
    override fun isApproved(authorizationRequest: AuthorizationRequest, userAuthentication: Authentication): Boolean {
        // if this request is already approved, pass that info through
        // (this flag may be set by updateBeforeApproval, which can also do funny things with scopes, etc)

        return if (authorizationRequest.isApproved) {
            true
        } else {
            // if not, check to see if the user has approved it
            // TODO: make parameter name configurable?
            authorizationRequest.approvalParameters["user_oauth_approval"].toBoolean()
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
        userAuthentication: Authentication
    ): AuthorizationRequest {
        //First, check database to see if the user identified by the userAuthentication has stored an approval decision

        val userId = userAuthentication.name
        val clientId = authorizationRequest.clientId

        //lookup ApprovedSites by userId and clientId
        var alreadyApproved = false

        // find out if we're supposed to force a prompt on the user or not
        val prompt = authorizationRequest.extensions[ConnectRequestParameters.PROMPT] as String?
        val prompts = prompt?.let { Prompt.parseSet(it) } ?: emptySet()

        if (Prompt.CONSENT !in prompts) {
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
                        authorizationRequest.extensions[ConnectRequestParameters.APPROVED_SITE] = apId
                        authorizationRequest.isApproved = true
                        alreadyApproved = true

                        setAuthTime(authorizationRequest)
                    }
                }
            }

            if (!alreadyApproved) {
                val ws = whitelistedSiteService.getByClientId(clientId)
                if (ws != null && systemScopes.scopesMatch(ws.allowedScopes, authorizationRequest.scope)) {
                    authorizationRequest.isApproved = true

                    setAuthTime(authorizationRequest)
                }
            }
        }

        return authorizationRequest
    }


    override fun updateAfterApproval(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication
    ): AuthorizationRequest {
        val userId = userAuthentication.name
        val clientId = authorizationRequest.clientId
        val client = clientDetailsService.loadClientByClientId(clientId)

        // This must be re-parsed here because SECOAUTH forces us to call things in a strange order
        if (authorizationRequest.approvalParameters["user_oauth_approval"].toBoolean()) {
            authorizationRequest.isApproved = true

            // process scopes from user input
            val allowedScopes: MutableSet<String> = hashSetOf()
            val approvalParams = authorizationRequest.approvalParameters

            //This is a scope parameter from the approval page. The value sent back should
            //be the scope string. Check to make sure it is contained in the client's
            //registered allowed scopes.
            approvalParams.asSequence()
                .filter { it.key.startsWith("scope_")  }
                .map { it.value }
                //Make sure this scope is allowed for the given client
                .filterTo(allowedScopes) { scope -> systemScopes.scopesMatch(client.scope, setOf(scope)) }


            // inject the user-allowed scopes into the auth request
            authorizationRequest.setScope(allowedScopes)

            //Only store an ApprovedSite if the user has checked "remember this decision":
            val remember = authorizationRequest.approvalParameters["remember"]
            if (!remember.isNullOrEmpty() && remember != "none") {
                var timeout: Date? = null
                if (remember == "one-hour") {
                    // set the timeout to one hour from now
                    val cal = Calendar.getInstance()
                    cal.add(Calendar.HOUR, 1)
                    timeout = cal.time
                }

                val newSite = approvedSiteService.createApprovedSite(clientId, userId, timeout, allowedScopes)
                val newSiteId = newSite.id.toString()
                authorizationRequest.extensions[ConnectRequestParameters.APPROVED_SITE] = newSiteId
            }

            setAuthTime(authorizationRequest)
        }

        return authorizationRequest
    }

    /**
     * Get the auth time out of the current session and add it to the
     * auth request in the extensions map.
     *
     */
    private fun setAuthTime(authorizationRequest: AuthorizationRequest) {
        // Get the session auth time, if we have it, and store it in the request
        val attr = RequestContextHolder.currentRequestAttributes() as ServletRequestAttributes? ?: return
        val session = attr.request.session ?: return
        val authTime = session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP) as Date? ?: return
        val authTimeString = authTime.time.toString()
        authorizationRequest.extensions[AuthenticationTimeStamper.AUTH_TIMESTAMP] = authTimeString
    }

    override fun getUserApprovalRequest(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication
    ): Map<String, Any> {
        val model: MutableMap<String, Any> = HashMap()
        // In case of a redirect we might want the request parameters to be included
        model.putAll(authorizationRequest.requestParameters)
        return model
    }
}
