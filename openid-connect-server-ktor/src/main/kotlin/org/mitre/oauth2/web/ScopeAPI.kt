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
package org.mitre.oauth2.web

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.openid.connect.web.RootController
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.requireClientRole
import org.mitre.web.util.requireUserRole
import org.mitre.web.util.scopeService

/**
 * @author jricher
 */
// @Controller
// @RequestMapping("/" + ScopeAPI.URL)
// @PreAuthorize("hasRole('ROLE_USER')")
object ScopeAPI : KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/scopes") {
            authenticate {
                get { getAll() }
                get("/{id}") { getScope() }
                put("/{id}") { updateScope() }
                post { createScope() }
                delete("/{id}") { deleteScope() }

            }
        }
    }

    //    @RequestMapping(value = [""], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAll() {
        requireClientRole().getOrElse { return }

        return call.respondJson(scopeService.all)
    }

    //    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.getScope() {
        requireClientRole().getOrElse { return }
        val id = call.parameters["id"]!!.toLong()

        val scope = scopeService.getById(id)

        if (scope != null) {
            return call.respondJson(scope)
        } else {
            logger.error("getScope failed; scope not found: $id", )
            return jsonErrorView(OAuthErrorCodes.INVALID_SCOPE, errorMessage = "The requested scope with id $id could not be found.", code = HttpStatusCode.NotFound)
        }
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.updateScope() {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN).getOrElse { return }

        val id = call.parameters["id"]!!.toLong()
        val jsonText = call.receiveText().takeIf { it.isNotEmpty() }

        val existing = scopeService.getById(id)
        val scope: SystemScope? = jsonText?.let { oidJson.decodeFromString(it) }

        when {
            existing == null || scope == null -> {
                logger.error("updateScope failed; scope with id $id not found.")
                return jsonErrorView(
                    OAuthErrorCodes.INVALID_SCOPE,
                    HttpStatusCode.NotFound,
                    "Could not update scope. The scope with id $id could not be found."
                )
            }
            existing.id == scope.id -> {
                // sanity check
                return call.respondJson(scopeService.save(scope))
            }
            else -> {
                logger.error("updateScope failed; scope ids to not match: got ${existing.id} and ${scope.id}")

                return jsonErrorView(
                    errorCode = OAuthErrorCodes.INVALID_REQUEST,
                    errorMessage = "Could not update scope. Scope ids to not match: got ${existing.id} and ${scope.id}",
                )
            }
        }
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = [""], method = [RequestMethod.POST], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.createScope() {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN).getOrElse { return }

        val jsonText = call.receiveText()

        val inputScope = jsonText.let { oidJson.decodeFromString<SystemScope>(it) }

        val alreadyExists = scopeService.getByValue(inputScope.value!!)
        if (alreadyExists != null) {
            //Error, cannot save a scope with the same value as an existing one
            logger.error("Error: attempting to save a scope with a value that already exists: ${inputScope.value}")
            return jsonErrorView(
                OAuthErrorCodes.INVALID_REQUEST,
                HttpStatusCode.Conflict,
                "A scope with value ${inputScope.value} already exists, please choose a different value."
            )
        }

        val savedScope = scopeService.save(inputScope)

        if (savedScope?.id != null) {
            return call.respondJson(savedScope)
        } else {
            logger.error("createScope failed; JSON was invalid: $oidJson")
            return jsonErrorView(
                OAuthErrorCodes.SERVER_ERROR,
                HttpStatusCode.BadRequest,
                "Could not save new scope $savedScope. The scope service failed to return a saved entity."
            )
        }
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    private suspend fun RoutingContext.deleteScope() {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN).getOrElse { return }
        val id = call.parameters["id"]!!.toLong()

        val existing = scopeService.getById(id)

        if (existing == null) {
            logger.error("deleteScope failed; scope with id $id not found.")
            return jsonErrorView(
                OAuthErrorCodes.INVALID_SCOPE,
                HttpStatusCode.NotFound,
                "Could not delete scope. The requested scope with id $id could not be found."
            )
        }

        scopeService.remove(existing)
        return call.respond(HttpStatusCode.OK)
    }

    const val URL: String = RootController.API_URL + "/scopes"

    private val logger = getLogger()
}

