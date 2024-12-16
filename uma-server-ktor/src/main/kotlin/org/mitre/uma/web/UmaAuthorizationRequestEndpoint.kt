package org.mitre.uma.web

import io.github.pdvrieze.auth.TokenAuthentication
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.asString
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.claimsProcessingService
import org.mitre.web.util.permissionService
import org.mitre.web.util.requireScope
import org.mitre.web.util.tokenService
import org.mitre.web.util.umaTokenService

/**
 * @author jricher
 */
//@Controller
//@RequestMapping("/authz_request")
object UmaAuthorizationRequestEndpoint : KtorEndpoint {
    override fun Route.addRoutes() {
        route("/authz_request") {
            authenticate {
                post { authorizationRequest() }
            }
        }
    }

    /*
        @Autowired
        private lateinit var permissionService: PermissionService

        @Autowired
        private lateinit var tokenService: OAuth2TokenEntityService

        @Autowired
        private lateinit var claimsProcessingService: ClaimsProcessingService

        @Autowired
        private lateinit var umaTokenService: UmaTokenService
    */

    //    @RequestMapping(method = [RequestMethod.POST], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.authorizationRequest() {
        val auth: TokenAuthentication = (requireScope(SystemScopeService.UMA_AUTHORIZATION_SCOPE).getOrElse { return } as? TokenAuthentication)
            ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Invalid authentication")

        val obj = oidJson.parseToJsonElement(call.receiveText())
        if (obj !is JsonObject) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Malformed JSON request.")
        }

        val rawTicket = obj[TICKET]?.asString()
        if (rawTicket == null) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing JSON elements.")
        }

        val incomingRpt = obj[RPT]?.let {
            tokenService.readAccessToken(it.asString())
        }

        val ticket = permissionService.getByTicket(rawTicket)
        if (ticket == null) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "invalid_ticket")
        }

        val rs = ticket.permission.resourceSet
        if (rs.policies.isNullOrEmpty()) {
            // the required claims are empty, this resource has no way to be authorized
            return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED, "This resource set can not be accessed.")
        }

        // claims weren't empty or missing, we need to check against what we have

        val result = claimsProcessingService.claimsAreSatisfied(rs, ticket)


        if (result.isSatisfied) {
            // the service found what it was looking for, issue a token
            // we need to downscope this based on the required set that was matched if it was matched
            val token = umaTokenService.createRequestingPartyToken(auth, ticket, result.matched!!)

            // if we have an inbound RPT, throw it out because we're replacing it
            if (incomingRpt != null) {
                tokenService.revokeAccessToken(incomingRpt)
            }

            return call.respondJson(buildJsonObject { put("rpt", token.value) })
        }
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
        return call.respondJson(entity)
    }

    // Logger for this class
    private val logger = getLogger()

    const val RPT: String = "rpt"
    const val TICKET: String = "ticket"
    const val URL: String = "authz_request"
}
