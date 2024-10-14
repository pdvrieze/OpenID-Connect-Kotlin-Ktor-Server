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
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.requireRole
import org.mitre.web.util.whitelistedSiteService

/**
 * @author jricher
 */
//@Controller
//@RequestMapping("/" + WhitelistAPI.URL)
//@PreAuthorize("hasRole('ROLE_USER')")
object WhitelistAPI : KtorEndpoint {
    override fun Route.addRoutes() {
        route("/api/whitelist") {
            authenticate {
                get() { getAllWhitelistedSites() }
                post { addNewWhitelistedSite() }
                put("/{id}") { updateWhitelistedSite() }
                delete("/{id}") { deleteWhitelistedSite() }
                get("/{id}") { getWhitelistedSite() }
            }

        }
    }

//    @Autowired
//    private lateinit var whitelistService: WhitelistedSiteService

    /**
     * Get a list of all whitelisted sites
     */
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAllWhitelistedSites() {
        requireRole(GrantedAuthority.ROLE_USER) { return }

        return call.respondJson(whitelistedSiteService.all)
    }

    /**
     * Create a new whitelisted site
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.addNewWhitelistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val json: JsonObject

        val whitelist: WhitelistedSite
        try {
            json = Json.parseToJsonElement(call.receiveText()).jsonObject
            whitelist = Json.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("addNewWhitelistedSite failed due to SerializationException", e)
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Could not save new whitelisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance.")
        } catch (e: IllegalStateException) {
            logger.error("addNewWhitelistedSite failed due to IllegalStateException", e)
            return jsonErrorView(
                OAuthErrorCodes.SERVER_ERROR,
                HttpStatusCode.BadRequest,
                "Could not save new whitelisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance.",
            )
        }

        // save the id of the person who created this
        whitelist.creatorUserId = p.name

        val newWhitelist = whitelistedSiteService.saveNew(whitelist)
        return call.respondJson(newWhitelist)
    }

    /**
     * Update an existing whitelisted site
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.updateWhitelistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val id = call.parameters["id"]!!.toLong()
        val json: JsonObject

        val whitelist: WhitelistedSite
        try {
            json = Json.parseToJsonElement(call.receiveText()).jsonObject
            whitelist = Json.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("updateWhitelistedSite failed due to SerializationException", e)
            return jsonErrorView(
                OAuthErrorCodes.INVALID_REQUEST,
                "Could not update whitelisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            )
        } catch (e: IllegalStateException) {
            logger.error("updateWhitelistedSite failed due to IllegalStateException", e)
            return jsonErrorView(
                OAuthErrorCodes.SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not update whitelisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            )
        }

        val whitelistService = whitelistedSiteService

        val oldWhitelist = whitelistService.getById(id) ?: run {
            logger.error("updateWhitelistedSite failed; whitelist with id $id could not be found.")
            return jsonErrorView(OAuthErrorCodes.INVALID_REQUEST, "Could not update whitelisted site. The requested whitelisted site with id ${id} could not be found.")
        }

        return call.respondJson(whitelistService.update(oldWhitelist, whitelist))
    }

    /**
     * Delete a whitelisted site
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    suspend fun RoutingContext.deleteWhitelistedSite() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val id = call.parameters["id"]!!.toLong()
        val whitelistService = whitelistedSiteService

        val whitelist = whitelistService.getById(id) ?: kotlin.run {
            logger.error("deleteWhitelistedSite failed; whitelist with id $id could not be found.")
            return call.respond(HttpStatusCode.NotFound)
        }

        whitelistService.remove(whitelist)
        return call.respond(HttpStatusCode.OK)
    }

    /**
     * Get a single whitelisted site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getWhitelistedSite() {
        val id = call.parameters["id"]!!.toLong()

        val whitelist = whitelistedSiteService.getById(id) ?: kotlin.run {
            jsonErrorView(
                OAuthErrorCodes.INVALID_REQUEST, HttpStatusCode.NotFound,
                "The requested whitelisted site with id ${id} could not be found."
            )
        }

        return call.respondJson(whitelist)
    }

    const val URL: String = RootController.API_URL + "/whitelist"

    /**
     * Logger for this class
     */
    private val logger = getLogger<WhitelistAPI>()
}
