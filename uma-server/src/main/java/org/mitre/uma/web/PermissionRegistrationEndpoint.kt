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

import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import com.google.gson.JsonParser
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.web.AuthenticationUtilities.ensureOAuthScope
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.uma.service.PermissionService
import org.mitre.uma.service.ResourceSetService
import org.mitre.util.JsonUtils.getAsLong
import org.mitre.util.JsonUtils.getAsStringSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod

/**
 * @author jricher
 */
@Controller
@RequestMapping("/" + PermissionRegistrationEndpoint.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class PermissionRegistrationEndpoint {
    @Autowired
    private lateinit var permissionService: PermissionService

    @Autowired
    private lateinit var resourceSetService: ResourceSetService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    private val parser = JsonParser()

    @RequestMapping(method = [RequestMethod.POST], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun getPermissionTicket(@RequestBody jsonString: String?, m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        try {
            // parse the permission request

            val el = parser.parse(jsonString)
            if (el.isJsonObject) {
                val o = el.asJsonObject

                val rsid = getAsLong(o, "resource_set_id")
                var scopes: Set<String>? = getAsStringSet(o, "scopes")

                if (rsid == null || scopes.isNullOrEmpty()) {
                    // missing information
                    m.addAttribute("code", HttpStatus.BAD_REQUEST)
                    m.addAttribute("errorMessage", "Missing required component of permission registration request.")
                    return JsonErrorView.VIEWNAME
                }

                // trim any restricted scopes
                val scopesRequested: Set<SystemScope> =
                    scopeService.removeRestrictedAndReservedScopes(scopeService.fromStrings(scopes)!!)

                scopes = scopeService.toStrings(scopesRequested)

                val resourceSet = resourceSetService.getById(rsid)

                // requested resource set doesn't exist
                if (resourceSet == null) {
                    m.addAttribute("code", HttpStatus.NOT_FOUND)
                    m.addAttribute("errorMessage", "Requested resource set not found: $rsid")
                    return JsonErrorView.VIEWNAME
                }

                // authorized user of the token doesn't match owner of the resource set
                if (resourceSet.owner != auth.name) {
                    m.addAttribute("code", HttpStatus.FORBIDDEN)
                    m.addAttribute("errorMessage", "Party requesting permission is not owner of resource set, expected " + resourceSet.owner + " got " + auth.name)
                    return JsonErrorView.VIEWNAME
                }

                // create the permission
                val permission = permissionService.createTicket(resourceSet, scopes!!)

                if (permission != null) {
                    // we've created the permission, return the ticket
                    val out = JsonObject()
                    out.addProperty("ticket", permission.ticket)
                    m.addAttribute("entity", out)

                    m.addAttribute("code", HttpStatus.CREATED)

                    return JsonEntityView.VIEWNAME
                } else {
                    // there was a failure creating the permission object

                    m.addAttribute("code", HttpStatus.INTERNAL_SERVER_ERROR)
                    m.addAttribute("errorMessage", "Unable to save permission and generate ticket.")

                    return JsonErrorView.VIEWNAME
                }
            } else {
                // malformed request
                m.addAttribute("code", HttpStatus.BAD_REQUEST)
                m.addAttribute("errorMessage", "Malformed JSON request.")
                return JsonErrorView.VIEWNAME
            }
        } catch (e: JsonParseException) {
            // malformed request
            m.addAttribute("code", HttpStatus.BAD_REQUEST)
            m.addAttribute("errorMessage", "Malformed JSON request.")
            return JsonErrorView.VIEWNAME
        }
    }

    companion object {
        // Logger for this class
        private val logger: Logger = LoggerFactory.getLogger(PermissionRegistrationEndpoint::class.java)

        const val URL: String = "permission"
    }
}
