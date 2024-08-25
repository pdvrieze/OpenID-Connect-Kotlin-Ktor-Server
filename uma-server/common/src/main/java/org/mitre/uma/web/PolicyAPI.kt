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

import kotlinx.serialization.json.Json
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.web.RootController
import org.mitre.uma.model.Policy
import org.mitre.uma.service.ResourceSetService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod

/**
 * API for managing policies on resource sets.
 *
 * @author jricher
 */
@Controller
@RequestMapping("/" + PolicyAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class PolicyAPI {

    @Autowired
    private lateinit var resourceSetService: ResourceSetService

    /**
     * List all resource sets for the current user
     */
    @RequestMapping(value = [""], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun getResourceSetsForCurrentUser(m: Model, auth: Authentication): String {
        val resourceSets = resourceSetService.getAllForOwner(auth.name)

        m.addAttribute(JsonEntityView.ENTITY, resourceSets)

        return JsonEntityView.VIEWNAME
    }

    /**
     * Get the indicated resource set
     */
    @RequestMapping(value = ["/{rsid}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun getResourceSet(@PathVariable(value = "rsid") rsid: Long, m: Model, auth: Authentication): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        m.addAttribute(JsonEntityView.ENTITY, rs)

        return JsonEntityView.VIEWNAME
    }

    /**
     * Delete the indicated resource set
     */
    @RequestMapping(value = ["/{rsid}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun deleteResourceSet(@PathVariable(value = "rsid") rsid: Long, m: Model, auth: Authentication): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        resourceSetService.remove(rs)
        m.addAttribute(HttpCodeView.CODE, HttpStatus.NO_CONTENT)
        return HttpCodeView.VIEWNAME
    }

    /**
     * List all the policies for the given resource set
     */
    @RequestMapping(value = ["/{rsid}" + POLICYURL], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun getPoliciesForResourceSet(@PathVariable(value = "rsid") rsid: Long, m: Model, auth: Authentication): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        m.addAttribute(JsonEntityView.ENTITY, rs.policies)

        return JsonEntityView.VIEWNAME
    }

    /**
     * Create a new policy on the given resource set
     */
    @RequestMapping(value = ["/{rsid}" + POLICYURL], method = [RequestMethod.POST], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun createNewPolicyForResourceSet(
        @PathVariable(value = "rsid") rsid: Long,
        @RequestBody jsonString: String,
        m: Model,
        auth: Authentication
    ): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        val p = Json.decodeFromString<Policy>(jsonString)

        if (p.id != null) {
            logger.warn("Tried to add a policy with a non-null ID: " + p.id)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            return HttpCodeView.VIEWNAME
        }

        for (claim in p.claimsRequired!!) {
            if (claim.id != null) {
                logger.warn("Tried to add a policy with a non-null claim ID: " + claim.id)
                m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
                return HttpCodeView.VIEWNAME
            }
        }

        val rsPolicies = rs.policies.toMutableList()
        rsPolicies.add(p)
        val saved = resourceSetService.update(rs, rs.copy(policies = rsPolicies))

        // find the new policy object
        val newPolicies = saved.policies.toSet() - rsPolicies.toSet()

        if (newPolicies.size == 1) {
            val newPolicy = newPolicies.iterator().next()
            m.addAttribute(JsonEntityView.ENTITY, newPolicy)
            return JsonEntityView.VIEWNAME
        } else {
            logger.warn("Unexpected result trying to add a new policy object: $newPolicies")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.INTERNAL_SERVER_ERROR)
            return HttpCodeView.VIEWNAME
        }
    }

    /**
     * Get a specific policy
     */
    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun getPolicy(
        @PathVariable(value = "rsid") rsid: Long,
        @PathVariable(value = "pid") pid: Long,
        m: Model,
        auth: Authentication
    ): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        for (policy in rs.policies!!) {
            if (policy.id == pid) {
                // found it!
                m.addAttribute(JsonEntityView.ENTITY, policy)
                return JsonEntityView.VIEWNAME
            }
        }

        // if we made it this far, we haven't found it
        m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
        return HttpCodeView.VIEWNAME
    }

    /**
     * Update a specific policy
     */
    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.PUT], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun setClaimsForResourceSet(
        @PathVariable(value = "rsid") rsid: Long,
        @PathVariable(value = "pid") pid: Long,
        @RequestBody jsonString: String,
        m: Model,
        auth: Authentication
    ): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            return HttpCodeView.VIEWNAME
        }

        if (rs.owner != auth.name) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // authenticated user didn't match the owner of the resource set
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return HttpCodeView.VIEWNAME
        }

        val p = Json.decodeFromString<Policy>(jsonString)

        if (pid != p.id) {
            logger.warn("Policy ID mismatch, expected " + pid + " got " + p.id)

            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            return HttpCodeView.VIEWNAME
        }

        for (policy in rs.policies) {
            if (policy.id == pid) {
                // found it!

                // find the existing claim IDs, make sure we're not overwriting anything from another policy

                val claimIds: MutableSet<Long?> = HashSet()
                for (claim in policy.claimsRequired!!) {
                    claimIds.add(claim.id)
                }

                for (claim in p.claimsRequired!!) {
                    if (claim.id != null && !claimIds.contains(claim.id)) {
                        logger.warn("Tried to add a policy with a an unmatched claim ID: got " + claim.id + " expected " + claimIds)
                        m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
                        return HttpCodeView.VIEWNAME
                    }
                }

                // update the existing object with the new values
                policy.claimsRequired = p.claimsRequired
                policy.name = p.name
                policy.scopes = p.scopes

                resourceSetService.update(rs, rs)

                m.addAttribute(JsonEntityView.ENTITY, policy)
                return JsonEntityView.VIEWNAME
            }
        }

        // if we made it this far, we haven't found it
        m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
        return HttpCodeView.VIEWNAME
    }

    /**
     * Delete a specific policy
     */
    @RequestMapping(value = ["/{rsid}" + POLICYURL + "/{pid}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun deleteResourceSet(
        @PathVariable("rsid") rsid: Long,
        @PathVariable(value = "pid") pid: Long,
        m: Model,
        auth: Authentication
    ): String {
        val rs = resourceSetService.getById(rsid)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR, "not_found")
            return JsonErrorView.VIEWNAME
        }

        if (auth.name != rs.owner) {
            logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

            // it wasn't issued to this user
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
            return JsonErrorView.VIEWNAME
        }


        for (policy in rs.policies!!) {
            if (policy.id == pid) {
                // found it!
                val newPolicies = rs.policies.toMutableList().apply { remove(policy) }
                resourceSetService.update(rs, rs.copy(policies = newPolicies))

                m.addAttribute(HttpCodeView.CODE, HttpStatus.NO_CONTENT)
                return HttpCodeView.VIEWNAME
            }
        }

        // if we made it this far, we haven't found it
        m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
        return HttpCodeView.VIEWNAME
    }

    companion object {
        // Logger for this class
        private val logger: Logger = LoggerFactory.getLogger(PolicyAPI::class.java)

        const val URL: String = RootController.API_URL + "/resourceset"
        const val POLICYURL: String = "/policy"
    }
}
