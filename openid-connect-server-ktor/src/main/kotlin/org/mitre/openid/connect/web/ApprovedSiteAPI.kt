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
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.encodeToJsonElement
import org.mitre.oauth2.exception.OAuthErrorCodes.ACCESS_DENIED
import org.mitre.oauth2.exception.OAuthErrorCodes.INVALID_REQUEST
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.view.jsonApprovedSiteView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.approvedSiteService
import org.mitre.web.util.requireUserRole

/**
 * @author jricher
 */
//@RequestMapping("/" + ApprovedSiteAPI.URL)
//@PreAuthorize("hasRole('ROLE_USER')")
object ApprovedSiteAPI : KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/approved") {
            authenticate {
                get { getAllApprovedSites() }
                delete("/{id}") { deleteApprovedSite() }
                get("/{id}") { getApprovedSite() }
            }
        }
    }

    /**
     * Get a list of all of this user's approved sites
     */
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAllApprovedSites() {
        val p = requireUserRole().getOrElse { return }

        val all = approvedSiteService.getByUserId(p.userId).map {
            val approvedAccessTokens = approvedSiteService.getApprovedAccessTokens(it).mapTo(HashSet()) { t -> t.id!! }
            ApprovedSite.SerialDelegate(it, approvedAccessTokens)
        }

        return jsonApprovedSiteView(oidJson.encodeToJsonElement(all))
    }

    /**
     * Delete an approved site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    suspend fun RoutingContext.deleteApprovedSite() {
        val p = requireUserRole().getOrElse { return }
        val id = call.parameters["id"]!!.toLong()

        val approvedSite = approvedSiteService.getById(id)
            ?: run {
                logger.error("deleteApprovedSite failed; no approved site found for id: $id")
                return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound,
                    "Could not delete approved site. The requested approved site with id: $id could not be found."
                )
            }

        if (approvedSite.userId != p.userId) {
            logger.error("deleteApprovedSite failed; principal ${p.userId} does not own approved site $id")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to delete this approved site. The approved site decision will not be deleted.")
        }

        approvedSiteService.remove(approvedSite)
        return call.respond(HttpStatusCode.NoContent)
    }

    /**
     * Get a single approved site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getApprovedSite() {
        val p = requireUserRole().getOrElse { return }
        val id = call.parameters["id"]!!.toLong()

        val approvedSite = approvedSiteService.getById(id)
            ?: run {
                logger.error("getApprovedSite failed; no approved site found for id: $id")
                return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound,
                                     "Could not delete approved site. The requested approved site with id: $id could not be found."
                )
            }
        if (approvedSite.userId != p.userId) {
            logger.error("getApprovedSite failed; principal ${p.userId} does not own approved site$id")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to view this approved site.")
        }

        val approvedAccessTokens = approvedSiteService.getApprovedAccessTokens(approvedSite).mapTo(HashSet()) { it.id!! }

        val d = ApprovedSite.SerialDelegate(approvedSite, approvedAccessTokens )
        return jsonApprovedSiteView(oidJson.encodeToJsonElement(d))
    }

    const val URL: String = "api/approved"

    /**
     * Logger for this class
     */
    private val logger = getLogger<ApprovedSiteAPI>()
}
