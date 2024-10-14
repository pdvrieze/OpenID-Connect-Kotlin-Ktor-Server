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
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.asStringSet
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.permissionService
import org.mitre.web.util.requireRole
import org.mitre.web.util.resourceSetService
import org.mitre.web.util.scopeService

/**
 * @author jricher
 */
//@RequestMapping("/permission")
//@PreAuthorize("hasRole('ROLE_USER')")
object PermissionRegistrationEndpoint: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/permission") {
            authenticate {
                post { getPermissionTicket() }
            }
        }
    }

//    @RequestMapping(method = [RequestMethod.POST], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.getPermissionTicket() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.UMA_PROTECTION_SCOPE) { return }

        try {
            // parse the permission request

            val obj = Json.parseToJsonElement(call.receiveText()) as? JsonObject
                ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Malformed JSON request.")

            val rsid = obj["resource_set_id"]?.jsonPrimitive?.long
            var scopes: Set<String>? = obj["scopes"].asStringSet()

            if (rsid == null || scopes.isNullOrEmpty()) {
                return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Missing required component of permission registration request.")
            }

            // trim any restricted scopes
            val scopeService = scopeService

            val scopesRequested: Set<SystemScope>? =
                scopeService.removeRestrictedAndReservedScopes(scopeService.fromStrings(scopes))

            scopes = scopeService.toStrings(scopesRequested) ?: emptySet()

            val resourceSet = resourceSetService.getById(rsid)
                ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, HttpStatusCode.NotFound, "Requested resource set not found: $rsid") // requested resource set doesn't exist

            // authorized user of the token doesn't match owner of the resource set
            if (resourceSet.owner != auth.name) {
                return jsonErrorView(
                    OAuthErrorCodes.ACCESS_DENIED,
                    "Party requesting permission is not owner of resource set, expected ${resourceSet.owner} got ${auth.name}"
                )
            }

            // create the permission
            val permission = permissionService.createTicket(resourceSet, scopes)

            if (permission != null) {
                // we've created the permission, return the ticket
                return call.respondJson(buildJsonObject {
                    put("ticket", permission.ticket)
                })
            }
            // there was a failure creating the permission object

            return jsonErrorView(OAuthErrorCodes.SERVER_ERROR, "Unable to save permission and generate ticket.")
        } catch (e: SerializationException) {
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Malformed JSON request.")
        }
    }

    // Logger for this class
    private val logger = getLogger<PermissionRegistrationEndpoint>()

    const val URL: String = "permission"
}
