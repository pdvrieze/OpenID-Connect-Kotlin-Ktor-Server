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

import org.mitre.openid.connect.service.ApprovedSiteService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonApprovedSiteView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.ModelMap
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import java.security.Principal

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + ApprovedSiteAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class ApprovedSiteAPI {
    @Autowired
    private lateinit var approvedSiteService: ApprovedSiteService

    /**
     * Get a list of all of this user's approved sites
     */
    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAllApprovedSites(m: ModelMap, p: Principal): String {
        val all = approvedSiteService.getByUserId(p.name)

        m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = all

        return org.mitre.openid.connect.view.JsonApprovedSiteView.VIEWNAME
    }

    /**
     * Delete an approved site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    fun deleteApprovedSite(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val approvedSite = approvedSiteService.getById(id)

        if (approvedSite == null) {
            logger.error("deleteApprovedSite failed; no approved site found for id: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] =
                "Could not delete approved site. The requested approved site with id: $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (approvedSite.userId != p.name) {
            logger.error(
                "deleteApprovedSite failed; principal "
                        + p.name + " does not own approved site" + id
            )
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] =
                "You do not have permission to delete this approved site. The approved site decision will not be deleted."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            m[HttpCodeView.CODE] = HttpStatus.OK
            approvedSiteService.remove(approvedSite)
        }

        return HttpCodeView.VIEWNAME
    }

    /**
     * Get a single approved site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getApprovedSite(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val approvedSite = approvedSiteService.getById(id)
        if (approvedSite == null) {
            logger.error("getApprovedSite failed; no approved site found for id: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested approved site with id: $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (approvedSite.userId != p.name) {
            logger.error(
                "getApprovedSite failed; principal "
                        + p.name + " does not own approved site" + id
            )
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "You do not have permission to view this approved site."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = approvedSite
            return org.mitre.openid.connect.view.JsonApprovedSiteView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/approved"

        /**
         * Logger for this class
         */
        private val logger = getLogger<ApprovedSiteAPI>()
    }
}
