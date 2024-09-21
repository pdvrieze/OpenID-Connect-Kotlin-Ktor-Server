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
package org.mitre.openid.connect.web

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.exception.OAuthErrorCodes.*
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.view.jsonEntityView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.blacklistedSiteService
import org.mitre.web.util.requireRole

/**
 * @author jricher
 */
//@Controller
//@RequestMapping("/api/blacklist")
//@PreAuthorize("hasRole('ROLE_ADMIN')")
class BlacklistAPI : KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/blacklist") {
            get { getAllBlacklistedSites() }
            post { addNewBlacklistedSite() }
            put("/{id}") { updateBlacklistedSite() }
            delete("/{id}") { deleteBlacklistedSite() }
            get("/{id}") { getBlacklistedSite() }
        }
    }

    /**
     * Get a list of all blacklisted sites
     */
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.getAllBlacklistedSites() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }

        return jsonEntityView(json.encodeToJsonElement(blacklistedSiteService.all))
    }

    /**
     * Create a new blacklisted site
     */
//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.addNewBlacklistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }

        try {
            val blacklist = Json.decodeFromString<BlacklistedSite>(call.receiveText())
            val newBlacklist = blacklistedSiteService.saveNew(blacklist)
            return jsonEntityView(json.encodeToJsonElement(newBlacklist))

        } catch (e: SerializationException) {
            logger.error("addNewBlacklistedSite failed due to SerializationException: ", e)
            return jsonErrorView(
                INVALID_REQUEST,
                "Could not save new blacklisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            )
        } catch (e: IllegalStateException) {
            logger.error("addNewBlacklistedSite failed due to IllegalStateException", e)
            return jsonErrorView(
                SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not save new blacklisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            )
        }
    }

    /**
     * Update an existing blacklisted site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.updateBlacklistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val id = call.parameters["id"]!!.toLong()


        val blacklist: BlacklistedSite

        try {
            blacklist = Json.decodeFromJsonElement(Json.parseToJsonElement(call.receiveText()).jsonObject)
        } catch (e: SerializationException) {
            logger.error("updateBlacklistedSite failed due to SerializationException", e)
            return jsonErrorView(INVALID_REQUEST,
                "Could not update blacklisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            )
        } catch (e: IllegalStateException) {
            logger.error("updateBlacklistedSite failed due to IllegalStateException", e)
            return jsonErrorView(SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not update blacklisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            )
        }

        val blacklistService = blacklistedSiteService

        val oldBlacklist = blacklistService.getById(id) ?: run {
            logger.error("updateBlacklistedSite failed; blacklist with id $id could not be found")
            return jsonErrorView(
                INVALID_REQUEST, HttpStatusCode.NotFound,
                "Could not update blacklisted site. The requested blacklist with id $id could not be found."
            )
        }

        val newBlacklist = blacklistService.update(oldBlacklist, blacklist)
        return jsonEntityView(this@BlacklistAPI.json.encodeToJsonElement(newBlacklist))
    }

    /**
     * Delete a blacklisted site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.deleteBlacklistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val id = call.parameters["id"]!!.toLong()

        val blacklistService = blacklistedSiteService

        val blacklist = blacklistService.getById(id) ?: run {
            logger.error("deleteBlacklistedSite failed; blacklist with id $id could not be found")
            return jsonErrorView(INVALID_REQUEST, "Could not delete blacklist. The requested blacklist with id $id could not be found.")
        }

        blacklistService.remove(blacklist)
        return call.respond(HttpStatusCode.OK)
    }

    /**
     * Get a single blacklisted site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.getBlacklistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val id = call.parameters["id"]!!.toLong()

        val blacklistService = blacklistedSiteService

        val blacklist = blacklistService.getById(id) ?: run {
            logger.error("getBlacklistedSite failed; blacklist with id $id could not be found")
            return jsonErrorView(INVALID_REQUEST, "Could not get blacklist. The requested blacklist with id $id could not be found.")
        }

        return jsonEntityView(json.encodeToJsonElement(blacklist))
    }

    companion object {
        const val URL: String = "api/blacklist"

        /**
         * Logger for this class
         */
        private val logger = getLogger<BlacklistAPI>()
    }
}
