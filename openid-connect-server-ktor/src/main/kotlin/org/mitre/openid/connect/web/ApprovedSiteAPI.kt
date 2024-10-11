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
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.encodeToJsonElement
import org.mitre.oauth2.exception.OAuthErrorCodes.ACCESS_DENIED
import org.mitre.oauth2.exception.OAuthErrorCodes.INVALID_REQUEST
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.view.jsonApprovedSiteView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.approvedSiteService
import org.mitre.web.util.requireRole

/**
 * @author jricher
 */
//@RequestMapping("/" + ApprovedSiteAPI.URL)
//@PreAuthorize("hasRole('ROLE_USER')")
object ApprovedSiteAPI : KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/approved") {
            get() { getAllApprovedSites() }
            delete("/{id}") { deleteApprovedSite() }
            get("/{id}") { getApprovedSite() }
        }
    }

    /**
     * Get a list of all of this user's approved sites
     */
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.getAllApprovedSites() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }

        val all = approvedSiteService.getByUserId(p.name)

        return jsonApprovedSiteView(json.encodeToJsonElement(all))
    }

    /**
     * Delete an approved site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    suspend fun PipelineContext<Unit, ApplicationCall>.deleteApprovedSite() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }
        val id = call.parameters["id"]!!.toLong()

        val approvedSite = approvedSiteService.getById(id)
            ?: run {
                logger.error("deleteApprovedSite failed; no approved site found for id: $id")
                return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound,
                    "Could not delete approved site. The requested approved site with id: $id could not be found."
                )
            }

        if (approvedSite.userId != p.name) {
            logger.error("deleteApprovedSite failed; principal ${p.name} does not own approved site$id")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to delete this approved site. The approved site decision will not be deleted.")
        }

        approvedSiteService.remove(approvedSite)
        return call.respond(HttpStatusCode.OK)
    }

    /**
     * Get a single approved site
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun PipelineContext<Unit, ApplicationCall>.getApprovedSite() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }
        val id = call.parameters["id"]!!.toLong()

        val approvedSite = approvedSiteService.getById(id)
            ?: run {
                logger.error("getApprovedSite failed; no approved site found for id: $id")
                return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound,
                                     "Could not delete approved site. The requested approved site with id: $id could not be found."
                )
            }
        if (approvedSite.userId != p.name) {
            logger.error("getApprovedSite failed; principal ${p.name} does not own approved site$id")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to view this approved site.")
        }

        return jsonApprovedSiteView(json.encodeToJsonElement(approvedSite))
    }

    const val URL: String = "api/approved"

    /**
     * Logger for this class
     */
    private val logger = getLogger<ApprovedSiteAPI>()
}
