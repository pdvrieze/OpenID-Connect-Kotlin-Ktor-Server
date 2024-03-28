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

import com.google.gson.Gson
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.util.toJavaId
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.web.RootController
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

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + ScopeAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class ScopeAPI {
    @Autowired
    private lateinit var scopeService: SystemScopeService

    private val gson = Gson()

    @RequestMapping(value = [""], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAll(m: ModelMap): String {
        val allScopes = scopeService.all

        m[JsonEntityView.ENTITY] = allScopes

        return JsonEntityView.VIEWNAME
    }

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getScope(@PathVariable("id") id: Long, m: ModelMap): String {
        val scope = scopeService.getById(id.toJavaId())

        if (scope != null) {
            m[JsonEntityView.ENTITY] = scope

            return JsonEntityView.VIEWNAME
        } else {
            logger.error("getScope failed; scope not found: $id")

            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] = "The requested scope with id $id could not be found."
            return JsonErrorView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun updateScope(@PathVariable("id") id: Long, @RequestBody json: String?, m: ModelMap): String {
        val existing = scopeService.getById(id.toJavaId())

        var scope = gson.fromJson(json, SystemScope::class.java)

        if (existing != null && scope != null) {
            if (existing.id == scope.id) {
                // sanity check

                scope = scopeService.save(scope)!!

                m[JsonEntityView.ENTITY] = scope

                return JsonEntityView.VIEWNAME
            } else {
                logger.error(
                    "updateScope failed; scope ids to not match: got "
                            + existing.id + " and " + scope.id
                )

                m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
                m[JsonErrorView.ERROR_MESSAGE] = ("Could not update scope. Scope ids to not match: got "
                        + existing.id + " and " + scope.id)
                return JsonErrorView.VIEWNAME
            }
        } else {
            logger.error("updateScope failed; scope with id $id not found.")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] = "Could not update scope. The scope with id $id could not be found."
            return JsonErrorView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = [""], method = [RequestMethod.POST], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun createScope(@RequestBody json: String, m: ModelMap): String {
        var scope = gson.fromJson(json, SystemScope::class.java)

        val alreadyExists = scopeService.getByValue(scope!!.value!!)
        if (alreadyExists != null) {
            //Error, cannot save a scope with the same value as an existing one
            logger.error("Error: attempting to save a scope with a value that already exists: " + scope.value)
            m[HttpCodeView.CODE] = HttpStatus.CONFLICT
            m[JsonErrorView.ERROR_MESSAGE] =
                "A scope with value " + scope.value + " already exists, please choose a different value."
            return JsonErrorView.VIEWNAME
        }

        scope = scopeService.save(scope)

        if (scope?.id != null) {
            m[JsonEntityView.ENTITY] = scope

            return JsonEntityView.VIEWNAME
        } else {
            logger.error("createScope failed; JSON was invalid: $json")
            m[HttpCodeView.CODE] = HttpStatus.BAD_REQUEST
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not save new scope $scope. The scope service failed to return a saved entity."
            return JsonErrorView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    fun deleteScope(@PathVariable("id") id: Long, m: ModelMap): String {
        val existing = scopeService.getById(id.toJavaId())

        if (existing != null) {
            scopeService.remove(existing)

            return HttpCodeView.VIEWNAME
        } else {
            logger.error("deleteScope failed; scope with id $id not found.")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[JsonErrorView.ERROR_MESSAGE] =
                "Could not delete scope. The requested scope with id $id could not be found."
            return JsonErrorView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/scopes"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(ScopeAPI::class.java)
    }
}
