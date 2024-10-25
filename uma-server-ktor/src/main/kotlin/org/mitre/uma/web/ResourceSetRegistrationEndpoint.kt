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
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.OAuthErrorCodes.INVALID_REQUEST
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.view.respondJson
import org.mitre.oauth2.web.AuthenticationUtilities.ensureOAuthScope
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.view.resourceSetEntityAbbreviatedView
import org.mitre.util.asString
import org.mitre.util.asStringSet
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.config
import org.mitre.web.util.requireRole
import org.mitre.web.util.resourceSetService
import org.mitre.web.util.scopeService

//@RequestMapping("/resource_set/resource_set")
//@PreAuthorize("hasRole('ROLE_USER')")
object ResourceSetRegistrationEndpoint: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/resource_set/resource_set") {
            authenticate {
                post { createResourceSet() }
                get("/{id}") { readResourceSet() }
                put("/{id}") { updateResourceSet() }
                delete("/{id}") { deleteResourceSet() }
                get { listResourceSets() }
            }
        }
    }

//    @RequestMapping(method = [RequestMethod.POST], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.createResourceSet() {
        val auth: Authentication = requireRole(GrantedAuthority.ROLE_USER) { return }
        val jsonString = call.receiveText()
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        var rs = parseResourceSet(jsonString) ?: run {
            logger.warn("Resource set registration missing body.")
            return jsonErrorView(INVALID_REQUEST, "Resource request was missing body.")
        }

        if (auth !is AuthenticatedAuthorizationRequest) {
            return jsonErrorView(INVALID_REQUEST, "This call must be made with an OAuth token")
        }

        // if it's an OAuth mediated call, it's on behalf of a client, so store that
        rs.clientId = auth.authorizationRequest.clientId
        rs.owner = auth.name // the username is going to be in the auth object

        rs = validateScopes(scopeService, rs)

        // there was no name (required) or there were no scopes (required)
        if (rs.name.isEmpty() || rs.scopes.isEmpty()) {
            logger.warn("Resource set registration missing one or more required fields.")
            return jsonErrorView(INVALID_REQUEST, "Resource request was missing one or more required fields.")
        }

        val saved = resourceSetService.saveNew(rs)

        return resourceSetEntityAbbreviatedView(saved, "${config.safeIssuer}$URL/${saved.id}", HttpStatusCode.Created)
    }

//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.readResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.UMA_PROTECTION_SCOPE) { return }
        val id = call.request.queryParameters["id"]!!.toLong()

        var rs = resourceSetService.getById(id)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "Resource not found")

    rs = validateScopes(scopeService, rs)

    if (auth.name != rs.owner) {
        logger.warn("Unauthorized resource set request from wrong user; expected " + rs.owner + " got " + auth.name)
        return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
    } else {
        return call.respondJson(rs)
    }
}

//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.updateResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.UMA_PROTECTION_SCOPE) { return }
        val id = call.request.queryParameters["id"]!!.toLong()

        val newRs = parseResourceSet(call.receiveText())

        if (// there were no scopes (required)
            (newRs == null // there was no resource set in the body
                    || newRs.name.isEmpty()) || newRs.scopes.isEmpty() || newRs.id == null || newRs.id != id // the IDs didn't match
        ) {
            logger.warn("Resource set registration missing one or more required fields.")
            return jsonErrorView(INVALID_REQUEST, "Resource request was missing one or more required fields.")
        }

        val rs = resourceSetService.getById(id) ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound)

        if (auth.name != rs.owner) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)
            return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
        }

        val saved = resourceSetService.update(rs, newRs)

        val location = "${config.issuer}$URL/${rs.id}"
        return resourceSetEntityAbbreviatedView(saved, location)
    }

//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.deleteResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.UMA_PROTECTION_SCOPE) { return }
        val id = call.request.queryParameters["id"]!!.toLong()

        val rs = resourceSetService.getById(id)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "Resource not found")

    if (auth.name != rs.owner) {
        logger.warn("Unauthorized resource set request from bad user; expected ${rs.owner} got ${auth.name}")
        return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
    }

    if (auth is AuthenticatedAuthorizationRequest &&
        auth.authorizationRequest.clientId != rs.clientId
    ) {
        logger.warn("Unauthorized resource set request from bad client; expected ${rs.clientId} got ${auth.authorizationRequest.clientId}")
        return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
    }

    // user and client matched
    resourceSetService.remove(rs)
    return call.respond(HttpStatusCode.NoContent)
}

//    @RequestMapping(method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.listResourceSets() {
        val auth = requireRole(GrantedAuthority.ROLE_USER,  SystemScopeService.UMA_PROTECTION_SCOPE) { return }

        val owner = auth.name

        val resourceSets: Collection<ResourceSet>
        if (auth is AuthenticatedAuthorizationRequest) {
            // if it's an OAuth mediated call, it's on behalf of a client, so look that up too
            resourceSets = resourceSetService.getAllForOwnerAndClient(owner, auth.authorizationRequest.clientId)
        } else {
            // otherwise get everything for the current user
            resourceSets = resourceSetService.getAllForOwner(owner)
        }

        // build the entity here and send to the display
        val ids: MutableSet<String> = HashSet()
        for (resourceSet in resourceSets) {
            ids.add(resourceSet.id.toString()) // add them all as strings so that gson renders them properly
        }

        return call.respondJson(ids)
    }

    private fun parseResourceSet(jsonString: String): ResourceSet? {
        try {
            val o = (Json.parseToJsonElement(jsonString) as? JsonObject) ?: return null

            return ResourceSet(
                id = o["id"]?.jsonPrimitive?.long,
                name = requireNotNull(o["name"], { "Missing resource name" }).asString(),
                uri = o["uri"]?.asString(),
                type = o["type"]?.asString(),
                scopes = requireNotNull(o["scopes"].asStringSet()),
                iconUri = o["icon_uri"]?.asString(),
            )
        } catch (e: SerializationException) {
            return null
        }
    }


    /**
     * Make sure the resource set doesn't have any restricted or reserved scopes.
     */
    private fun validateScopes(scopeService: SystemScopeService, rs: ResourceSet): ResourceSet {
        // scopes that the client is asking for
        val requestedScopes = scopeService.fromStrings(rs.scopes)

        // the scopes that the resource set can have must be a subset of the dynamically allowed scopes
        val allowedScopes = scopeService.removeRestrictedAndReservedScopes(requestedScopes!!)

        rs.scopes = scopeService.toStrings(allowedScopes)!!

        return rs
    }

    private val logger = getLogger<ResourceSetRegistrationEndpoint>()

    const val DISCOVERY_URL: String = "resource_set"
    const val URL: String = DISCOVERY_URL + "/resource_set"
}
