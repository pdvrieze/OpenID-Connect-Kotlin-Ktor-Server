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
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.Json
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.web.RootController
import org.mitre.uma.model.Policy
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.requireRole
import org.mitre.web.util.resourceSetService

/**
 * API for managing policies on resource sets.
 *
 * @author jricher
 */
//@RequestMapping("/api/resourceset")
//@PreAuthorize("hasRole('ROLE_USER')")
object PolicyAPI: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/api/resourceset") {
            authenticate {
                get { getResourceSetsForCurrentUser() }
                get("/{rsid}") { getResourceSet() }
                delete("/{rsid}") { deleteResourceSet() }
                get("/{rsid}/policy") { getPoliciesForResourceSet() }
                post("/{rsid}/policy") { createNewPolicyForResourceSet() }
                get("/{rsid}/policy/{pid}") { getPolicy() }
                put("/{rsid}/policy/{pid}") { setClaimsForResourceSet() }
                delete("/{rsid}/policy/{pid}") { deleteResourceSetPolicy() }
            }
        }
    }

    /**
     * List all resource sets for the current user
     */
//    @RequestMapping(value = [""], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.getResourceSetsForCurrentUser() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }

        return call.respondJson(resourceSetService.getAllForOwner(auth.name))
    }

    /**
     * Get the indicated resource set
     */
//    @RequestMapping(value = ["/{rsid}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.getResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected ${rs.owner} got ${auth.name}")
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        return call.respondJson(rs)
    }

    /**
     * Delete the indicated resource set
     */
//    @RequestMapping(value = ["/{rsid}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.deleteResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        resourceSetService.remove(rs)
        return call.respond(HttpStatusCode.NoContent)
    }

    /**
     * List all the policies for the given resource set
     */
//    @RequestMapping(value = ["/{rsid}" + POLICYURL], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.getPoliciesForResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()

        val rs = resourceSetService.getById(rsid)
            ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }
        return call.respondJson(rs.policies)
    }

    /**
     * Create a new policy on the given resource set
     */
//    @RequestMapping(value = ["/{rsid}" + POLICYURL], method = [RequestMethod.POST], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.createNewPolicyForResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected ${rs.owner} got ${auth.name}")
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        val p = Json.decodeFromString<Policy>(call.receiveText())

        if (p.id != null) {
            logger.warn("Tried to add a policy with a non-null ID: ${p.id}")
            return call.respond(HttpStatusCode.BadRequest)
        }

        for (claim in p.claimsRequired) {
            if (claim.id != null) {
                logger.warn("Tried to add a policy with a non-null claim ID: ${claim.id}")
                return call.respond(HttpStatusCode.BadRequest)
            }
        }

        val rsPolicies = rs.policies.toMutableList()
        rsPolicies.add(p)
        val saved = resourceSetService.update(rs, rs.copy(policies = rsPolicies))

        // find the new policy object
        val newPolicies = saved.policies.toSet() - rsPolicies.toSet()

        if (newPolicies.size != 1) {
            logger.warn("Unexpected result trying to add a new policy object: $newPolicies")
            return call.respond(HttpStatusCode.InternalServerError)
        }

        val newPolicy = newPolicies.iterator().next()
        return call.respondJson(newPolicy)
    }

    /**
     * Get a specific policy
     */
//    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.getPolicy() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()
        val pid = call.parameters["pid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        // if we made it this far, we haven't found it
        val policy = rs.policies.firstOrNull() { it.id == pid } ?: return call.respond(HttpStatusCode.NotFound)

        return call.respondJson(policy)
    }

    /**
     * Update a specific policy
     */
//    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.PUT], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.setClaimsForResourceSet() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()
        val pid = call.parameters["pid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected ${rs.owner} got ${auth.name}")
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        val p = Json.decodeFromString<Policy>(call.receiveText())

        if (pid != p.id) {
            logger.warn("Policy ID mismatch, expected $pid got ${p.id}")
            return call.respond(HttpStatusCode.BadRequest)
        }

        val policy = rs.policies.firstOrNull { it.id == pid } ?: return call.respond(HttpStatusCode.NotFound)

        // find the existing claim IDs, make sure we're not overwriting anything from another policy

        val claimIds: MutableSet<Long?> = HashSet()
        for (claim in policy.claimsRequired) {
            claimIds.add(claim.id)
        }

        for (claim in p.claimsRequired) {
            if (claim.id != null && !claimIds.contains(claim.id)) {
                logger.warn("Tried to add a policy with a an unmatched claim ID: got ${claim.id} expected $claimIds")
                return call.respond(HttpStatusCode.BadRequest)
            }
        }

        // update the existing object with the new values
        val newPolicy = policy.copy(
            name = p.name,
            claimsRequired = p.claimsRequired,
            scopes = p.scopes,
        )

        val newPolicies = rs.policies.map {
            when (it.id) {
                pid -> newPolicy
                else -> it
            }
        }

        val update = resourceSetService.update(rs, rs.copy(policies = newPolicies))
        return call.respondJson(update)
    }

    /**
     * Delete a specific policy
     */
//    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    private suspend fun PipelineContext<Unit, ApplicationCall>.deleteResourceSetPolicy() {
        val auth = requireRole(GrantedAuthority.ROLE_USER) { return }
        val rsid = call.parameters["rsid"]!!.toLong()
        val pid = call.parameters["pid"]!!.toLong()

        val rs = resourceSetService.getById(rsid) ?: return call.respond(HttpStatusCode.NotFound)

        if (auth.name != rs.owner) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)
            // authenticated user didn't match the owner of the resource set
            return call.respond(HttpStatusCode.Forbidden)
        }

        val newPolicies = rs.policies.filter { it.id == pid }
        // If we didn't shrink the list, the pid is not valid
        if (rs.policies.size == newPolicies.size) return call.respond(HttpStatusCode.NotFound)

        // found it!
        resourceSetService.update(rs, rs.copy(policies = newPolicies))

        return call.respond(HttpStatusCode.NoContent)
    }

    // Logger for this class
    private val logger = getLogger<PolicyAPI>()

    const val URL: String = RootController.API_URL + "/resourceset"
    const val POLICYURL: String = "/policy"
}
