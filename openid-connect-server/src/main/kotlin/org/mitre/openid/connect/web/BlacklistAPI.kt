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
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.slf4j.Logger
import org.slf4j.LoggerFactory
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
@RequestMapping("/" + BlacklistAPI.URL)
@PreAuthorize("hasRole('ROLE_ADMIN')")
class BlacklistAPI {
    @Autowired
    private lateinit var blacklistService: BlacklistedSiteService

    /**
     * Get a list of all blacklisted sites
     */
    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAllBlacklistedSites(m: ModelMap): String {
        val all = blacklistService.all

        m[JsonEntityView.ENTITY] = all

        return JsonEntityView.VIEWNAME
    }

    /**
     * Create a new blacklisted site
     */
    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun addNewBlacklistedSite(@RequestBody jsonString: String, m: ModelMap, p: Principal?): String {

        try {
            val blacklist = Json.decodeFromString<BlacklistedSite>(jsonString)
            val newBlacklist = blacklistService.saveNew(blacklist)
            m[JsonEntityView.ENTITY] = newBlacklist
        } catch (e: SerializationException) {
            logger.error("addNewBlacklistedSite failed due to SerializationException: ", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not save new blacklisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("addNewBlacklistedSite failed due to IllegalStateException", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not save new blacklisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        }

        return JsonEntityView.VIEWNAME
    }

    /**
     * Update an existing blacklisted site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun updateBlacklistedSite(
        @PathVariable("id") id: Long,
        @RequestBody jsonString: String,
        m: ModelMap,
        p: Principal?
    ): String {
        val json: JsonObject

        val blacklist: BlacklistedSite

        try {
            json = Json.parseToJsonElement(jsonString).jsonObject
            blacklist = Json.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("updateBlacklistedSite failed due to SerializationException", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update blacklisted site. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("updateBlacklistedSite failed due to IllegalStateException", e)
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update blacklisted site. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            return JsonErrorView.VIEWNAME
        }


        val oldBlacklist = blacklistService.getById(id)

        if (oldBlacklist == null) {
            logger.error("updateBlacklistedSite failed; blacklist with id $id could not be found")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not update blacklisted site. The requested blacklist with id " + id + "could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            val newBlacklist = blacklistService.update(oldBlacklist, blacklist)

            m[JsonEntityView.ENTITY] = newBlacklist

            return JsonEntityView.VIEWNAME
        }
    }

    /**
     * Delete a blacklisted site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    fun deleteBlacklistedSite(@PathVariable("id") id: Long, m: ModelMap): String {
        val blacklist = blacklistService.getById(id)

        if (blacklist == null) {
            logger.error("deleteBlacklistedSite failed; blacklist with id $id could not be found")
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not delete bladklist. The requested bladklist with id $id could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            m[HttpCodeView.CODE] = HttpStatus.OK
            blacklistService.remove(blacklist)
        }

        return HttpCodeView.VIEWNAME
    }

    /**
     * Get a single blacklisted site
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getBlacklistedSite(@PathVariable("id") id: Long, m: ModelMap): String {
        val blacklist = blacklistService.getById(id)
        if (blacklist == null) {
            logger.error("getBlacklistedSite failed; blacklist with id $id could not be found")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not delete bladklist. The requested bladklist with id $id could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            m[JsonEntityView.ENTITY] = blacklist

            return JsonEntityView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/blacklist"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(BlacklistAPI::class.java)
    }
}
