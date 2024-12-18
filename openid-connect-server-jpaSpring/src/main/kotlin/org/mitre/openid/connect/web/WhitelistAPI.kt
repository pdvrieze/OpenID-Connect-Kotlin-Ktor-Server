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

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.ModelMap
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import java.security.Principal

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + WhitelistAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class WhitelistAPI {
    @Autowired
    private lateinit var whitelistService: WhitelistedSiteService

    /**
     * Get a list of all whitelisted sites
     */
    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAllWhitelistedSites(m: ModelMap): String {
        val all = whitelistService.all

        m[JsonEntityView.ENTITY] = all

        return JsonEntityView.VIEWNAME
    }

    /**
     * Create a new whitelisted site
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun addNewWhitelistedSite(@RequestBody jsonString: String, m: ModelMap, p: Principal): String {
        val json: JsonObject

        val whitelist: WhitelistedSite
        try {
            json = oidJson.parseToJsonElement(jsonString).jsonObject
            whitelist = oidJson.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("addNewWhitelistedSite failed due to SerializationException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not save new whitelisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("addNewWhitelistedSite failed due to IllegalStateException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not save new whitelisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        }

        // save the id of the person who created this
        whitelist.creatorUserId = p.name

        val newWhitelist = whitelistService.saveNew(whitelist)

        m[JsonEntityView.ENTITY] = newWhitelist

        return JsonEntityView.VIEWNAME
    }

    /**
     * Update an existing whitelisted site
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun updateWhitelistedSite(
        @PathVariable("id") id: Long,
        @RequestBody jsonString: String,
        m: ModelMap,
        p: Principal?
    ): String {
        val json: JsonObject

        val whitelist: WhitelistedSite
        try {
            json = oidJson.parseToJsonElement(jsonString).jsonObject
            whitelist = oidJson.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("updateWhitelistedSite failed due to SerializationException", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update whitelisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("updateWhitelistedSite failed due to IllegalStateException", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update whitelisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        }

        val oldWhitelist = whitelistService.getById(id)

        if (oldWhitelist == null) {
            logger.error("updateWhitelistedSite failed; whitelist with id $id could not be found.")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update whitelisted site. The requested whitelisted site with id ${id} could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            val newWhitelist = whitelistService.update(oldWhitelist, whitelist)

            m[JsonEntityView.ENTITY] = newWhitelist

            return JsonEntityView.VIEWNAME
        }
    }

    /**
     * Delete a whitelisted site
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    fun deleteWhitelistedSite(@PathVariable("id") id: Long, m: ModelMap): String {
        val whitelist = whitelistService.getById(id)

        if (whitelist == null) {
            logger.error("deleteWhitelistedSite failed; whitelist with id $id could not be found.")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not delete whitelisted site. The requested whitelisted site with id ${id} could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            m[HttpCodeView.CODE] = HttpStatus.OK
            whitelistService.remove(whitelist)
        }

        return HttpCodeView.VIEWNAME
    }

    /**
     * Get a single whitelisted site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getWhitelistedSite(@PathVariable("id") id: Long, m: ModelMap): String {
        val whitelist = whitelistService.getById(id)
        if (whitelist == null) {
            logger.error("getWhitelistedSite failed; whitelist with id $id could not be found.")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] = "The requested whitelisted site with id ${id} could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            m[JsonEntityView.ENTITY] = whitelist

            return JsonEntityView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/whitelist"

        /**
         * Logger for this class
         */
        private val logger = getLogger<WhitelistAPI>()
    }
}
