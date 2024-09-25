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
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.OAuthErrorCodes.INVALID_REQUEST
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.web.AuthenticationUtilities.ensureOAuthScope
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.view.ResourceSetEntityView
import org.mitre.uma.view.resourceSetEntityAbbreviatedView
import org.mitre.util.OAuth2PrincipalJwtAuthentication
import org.mitre.util.asString
import org.mitre.util.asStringSet
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.config
import org.mitre.web.util.requireRole
import org.mitre.web.util.resourceSetService
import org.mitre.web.util.scopeService
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod


@Controller
@RequestMapping("/" + ResourceSetRegistrationEndpoint.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class ResourceSetRegistrationEndpoint: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/resource_set/resource_set") {
            post { createResourceSet() }
            get("/{id}") { readResourceSet() }
        }
    }

//    @RequestMapping(method = [RequestMethod.POST], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.createResourceSet() {
        val auth: Authentication = requireRole(GrantedAuthority.ROLE_USER) { return }
        val jsonString = call.receiveText()
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        var rs = parseResourceSet(jsonString) ?: run {
            logger.warn("Resource set registration missing body.")
            return jsonErrorView(INVALID_REQUEST, "Resource request was missing body.")
        }

        if (auth !is OAuth2PrincipalJwtAuthentication) {
            return jsonErrorView(INVALID_REQUEST, "This call must be made with an OAuth token")
        }

        // if it's an OAuth mediated call, it's on behalf of a client, so store that
        rs.clientId = auth.oAuth2Request.clientId
        rs.owner = auth.getName() // the username is going to be in the auth object

        rs = validateScopes(scopeService, rs)

        if (rs.name.isNullOrEmpty() // there was no name (required)
            || rs.scopes.isNullOrEmpty() // there were no scopes (required)
        ) {
            logger.warn("Resource set registration missing one or more required fields.")
            return jsonErrorView(INVALID_REQUEST, "Resource request was missing one or more required fields.")
        }

        val saved = resourceSetService.saveNew(rs)

        return resourceSetEntityAbbreviatedView(saved, "${config.safeIssuer}$URL/${saved.id}", HttpStatusCode.Created)
    }

//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.readResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER, SystemScopeService.UMA_PROTECTION_SCOPE) { return }
        val id = call.request.queryParameters["id"]!!.toLong()

        var rs = resourceSetService.getById(id)
            ?: return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, HttpStatusCode.NotFound, "Resource not found")

    rs = validateScopes(scopeService, rs)

    if (auth.name != rs.owner) {
        logger.warn("Unauthorized resource set request from wrong user; expected " + rs.owner + " got " + auth.name)
        return jsonErrorView(OAuthErrorCodes.ACCESS_DENIED)
    } else {
        return
        m.addAttribute(JsonEntityView.ENTITY, rs)
        return ResourceSetEntityView.VIEWNAME
    }
}

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.updateResourceSet(
        @PathVariable("id") id: Long,
        @RequestBody jsonString: String,
        m: Model,
        auth: Authentication
    ) {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val newRs = parseResourceSet(jsonString)

        if (// there were no scopes (required)
            (newRs == null // there was no resource set in the body
                    || newRs.name.isNullOrEmpty()) || newRs.scopes == null || newRs.id == null || newRs.id != id // the IDs didn't match
        ) {
            logger.warn("Resource set registration missing one or more required fields.")

            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Resource request was missing one or more required fields.")
            return JsonErrorView.VIEWNAME
        }

        val rs = resourceSetService.getById(id)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR, "not_found")
            return JsonErrorView.VIEWNAME
        } else {
            if (auth.name != rs.owner) {
                logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

                // it wasn't issued to this user
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else {
                val saved = resourceSetService.update(rs, newRs)

                m.addAttribute(JsonEntityView.ENTITY, saved)
                m.addAttribute(org.mitre.uma.view.ResourceSetEntityAbbreviatedView.LOCATION, config.issuer + URL + "/" + rs.id)
                return org.mitre.uma.view.ResourceSetEntityAbbreviatedView.VIEWNAME
            }
        }
    }

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.deleteResourceSet(@PathVariable("id") id: Long, m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val rs = resourceSetService.getById(id)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR, "not_found")
            return JsonErrorView.VIEWNAME
        } else {
            if (auth.name != rs.owner) {
                logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

                // it wasn't issued to this user
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else if (auth is OAuth2RequestAuthentication &&
                auth.oAuth2Request.clientId != rs.clientId
            ) {
                logger.warn("Unauthorized resource set request from bad client; expected " + rs.clientId + " got " + auth.oAuth2Request.clientId)

                // it wasn't issued to this client
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else {
                // user and client matched

                resourceSetService.remove(rs)

                m.addAttribute(HttpCodeView.CODE, HttpStatus.NO_CONTENT)
                return HttpCodeView.VIEWNAME
            }
        }
    }

    @RequestMapping(method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.listResourceSets(m: Model, auth: Authentication) {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val owner = auth.name

        val resourceSets: Collection<ResourceSet>
        if (auth is OAuth2RequestAuthentication) {
            // if it's an OAuth mediated call, it's on behalf of a client, so look that up too
            resourceSets = resourceSetService.getAllForOwnerAndClient(owner, auth.oAuth2Request.clientId)
        } else {
            // otherwise get everything for the current user
            resourceSets = resourceSetService.getAllForOwner(owner)
        }

        // build the entity here and send to the display
        val ids: MutableSet<String> = HashSet()
        for (resourceSet in resourceSets) {
            ids.add(resourceSet.id.toString()) // add them all as strings so that gson renders them properly
        }

        m.addAttribute(JsonEntityView.ENTITY, ids)
        return JsonEntityView.VIEWNAME
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

    companion object {
        private val logger = getLogger<ResourceSetRegistrationEndpoint>()

        const val DISCOVERY_URL: String = "resource_set"
        const val URL: String = DISCOVERY_URL + "/resource_set"
    }
}
