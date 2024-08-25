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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.web.AuthenticationUtilities.ensureOAuthScope
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.uma.service.ClaimsProcessingService
import org.mitre.uma.service.PermissionService
import org.mitre.uma.service.UmaTokenService
import org.mitre.util.asString
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + AuthorizationRequestEndpoint.URL)
class AuthorizationRequestEndpoint {
    @Autowired
    private lateinit var permissionService: PermissionService

    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    @Autowired
    private lateinit var claimsProcessingService: ClaimsProcessingService

    @Autowired
    private lateinit var umaTokenService: UmaTokenService

    @RequestMapping(method = [RequestMethod.POST], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun authorizationRequest(@RequestBody jsonString: String, m: Model, auth: Authentication?): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_AUTHORIZATION_SCOPE)

        val obj = Json.parseToJsonElement(jsonString)
        if (obj !is JsonObject) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Malformed JSON request.")
            return JsonErrorView.VIEWNAME
        }

        val rawTicket = obj[TICKET]?.asString()
        if(rawTicket == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Missing JSON elements.")
            return JsonErrorView.VIEWNAME
        }

        val incomingRpt = obj[RPT]?.let {
            tokenService.readAccessToken(it.asString())
        }

        val ticket = permissionService.getByTicket(rawTicket)
        if (ticket == null) {
            // ticket wasn't found, return an error
            m.addAttribute(HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR, "invalid_ticket")
            return JsonErrorView.VIEWNAME
        }

        val rs = ticket.permission.resourceSet
        if (rs.policies.isNullOrEmpty()) {
            // the required claims are empty, this resource has no way to be authorized

            m.addAttribute(JsonErrorView.ERROR, "not_authorized")
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "This resource set can not be accessed.")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return JsonErrorView.VIEWNAME
        }

        // claims weren't empty or missing, we need to check against what we have

        val result = claimsProcessingService.claimsAreSatisfied(rs, ticket)


        if (result.isSatisfied) {
            // the service found what it was looking for, issue a token

            // we need to downscope this based on the required set that was matched if it was matched

            val o2auth = auth as OAuth2Authentication

            val token = umaTokenService.createRequestingPartyToken(o2auth, ticket, result.matched!!)

            // if we have an inbound RPT, throw it out because we're replacing it
            if (incomingRpt != null) {
                tokenService.revokeAccessToken(incomingRpt)
            }

            val entity: Map<String, String> = mapOf("rpt" to token.value)

            m.addAttribute(JsonEntityView.ENTITY, entity)

            return JsonEntityView.VIEWNAME
        } else {
            // if we got here, the claim didn't match, forward the user to the claim gathering endpoint

            val entity = buildJsonObject {
                put(JsonErrorView.ERROR, "need_info")
                put("redirect_user", true)
                put("ticket", rawTicket)
                putJsonObject("error_details") {
                    putJsonObject("requesting_party_claims") {
                        putJsonArray("required_claims") {
                            for (claim in result.unmatched) {
                                addJsonObject {
                                    put("name", claim.name)
                                    put("friendly_name", claim.friendlyName)
                                    put("claim_type", claim.claimType)
                                    putJsonArray("claim_token_format") { addAll(claim.claimTokenFormat) }
                                    putJsonArray("issuer") { addAll(claim.issuer) }
                                }
                            }
                        }

                    }
                }
            }

            m.addAttribute(JsonEntityView.ENTITY, entity)
            return JsonEntityView.VIEWNAME
        }

    }

    companion object {
        // Logger for this class
        private val logger: Logger = LoggerFactory.getLogger(AuthorizationRequestEndpoint::class.java)

        const val RPT: String = "rpt"
        const val TICKET: String = "ticket"
        const val URL: String = "authz_request"
    }
}
