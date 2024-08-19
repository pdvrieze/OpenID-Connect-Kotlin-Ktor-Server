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

import com.google.gson.JsonParseException
import com.google.gson.JsonParser
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.web.AuthenticationUtilities.ensureOAuthScope
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.service.ResourceSetService
import org.mitre.uma.view.ResourceSetEntityAbbreviatedView
import org.mitre.uma.view.ResourceSetEntityView
import org.mitre.util.GsonUtils.getAsLong
import org.mitre.util.GsonUtils.getAsString
import org.mitre.util.GsonUtils.getAsStringSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.MimeTypeUtils
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod


@Controller
@RequestMapping("/" + ResourceSetRegistrationEndpoint.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class ResourceSetRegistrationEndpoint {
    @Autowired
    private lateinit var resourceSetService: ResourceSetService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var scopeService: SystemScopeService

    private val parser = JsonParser()

    @RequestMapping(method = [RequestMethod.POST], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun createResourceSet(@RequestBody jsonString: String, m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        var rs = parseResourceSet(jsonString)

        if (rs == null) { // there was no resource set in the body
            logger.warn("Resource set registration missing body.")

            m.addAttribute("code", HttpStatus.BAD_REQUEST)
            m.addAttribute("error_description", "Resource request was missing body.")
            return JsonErrorView.VIEWNAME
        }

        if (auth is OAuth2Authentication) {
            // if it's an OAuth mediated call, it's on behalf of a client, so store that
            rs.clientId = auth.oAuth2Request.clientId
            rs.owner = auth.getName() // the username is going to be in the auth object
        } else {
            // this one shouldn't be called if it's not OAuth
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "This call must be made with an OAuth token")
            return JsonErrorView.VIEWNAME
        }

        rs = validateScopes(rs)

        if (rs.name.isNullOrEmpty() // there was no name (required)
            || rs.scopes == null // there were no scopes (required)
        ) {
            logger.warn("Resource set registration missing one or more required fields.")

            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Resource request was missing one or more required fields.")
            return JsonErrorView.VIEWNAME
        }

        val saved = resourceSetService.saveNew(rs)

        m.addAttribute(HttpCodeView.CODE, HttpStatus.CREATED)
        m.addAttribute(JsonEntityView.ENTITY, saved)
        m.addAttribute(ResourceSetEntityAbbreviatedView.LOCATION, config.issuer + URL + "/" + saved.id)

        return ResourceSetEntityAbbreviatedView.VIEWNAME
    }

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun readResourceSet(@PathVariable("id") id: Long, m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        var rs = resourceSetService.getById(id)

        if (rs == null) {
            m.addAttribute("code", HttpStatus.NOT_FOUND)
            m.addAttribute("error", "not_found")
            return JsonErrorView.VIEWNAME
        } else {
            rs = validateScopes(rs)

            if (auth.name != rs.owner) {
                logger.warn("Unauthorized resource set request from wrong user; expected " + rs.owner + " got " + auth.name)

                // it wasn't issued to this user
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else {
                m.addAttribute(JsonEntityView.ENTITY, rs)
                return ResourceSetEntityView.VIEWNAME
            }
        }
    }

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MimeTypeUtils.APPLICATION_JSON_VALUE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun updateResourceSet(
        @PathVariable("id") id: Long,
        @RequestBody jsonString: String,
        m: Model,
        auth: Authentication
    ): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val newRs = parseResourceSet(jsonString)

        if (// there were no scopes (required)
            (newRs == null // there was no resource set in the body
                    || newRs.name.isNullOrEmpty()) || newRs.scopes == null || newRs.id == null || newRs.id != id // the IDs didn't match
        ) {
            logger.warn("Resource set registration missing one or more required fields.")

            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Resource request was missing one or more required fields.")
            return JsonErrorView.VIEWNAME
        }

        val rs = resourceSetService.getById(id)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR, "not_found")
            return JsonErrorView.VIEWNAME
        } else {
            if (auth.name != rs.owner) {
                logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

                // it wasn't issued to this user
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else {
                val saved = resourceSetService.update(rs, newRs)

                m.addAttribute(JsonEntityView.ENTITY, saved)
                m.addAttribute(ResourceSetEntityAbbreviatedView.LOCATION, config.issuer + URL + "/" + rs.id)
                return ResourceSetEntityAbbreviatedView.VIEWNAME
            }
        }
    }

    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun deleteResourceSet(@PathVariable("id") id: Long, m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val rs = resourceSetService.getById(id)

        if (rs == null) {
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR, "not_found")
            return JsonErrorView.VIEWNAME
        } else {
            if (auth.name != rs.owner) {
                logger.warn("Unauthorized resource set request from bad user; expected " + rs.owner + " got " + auth.name)

                // it wasn't issued to this user
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else if (auth is OAuth2Authentication &&
                auth.oAuth2Request.clientId != rs.clientId
            ) {
                logger.warn("Unauthorized resource set request from bad client; expected " + rs.clientId + " got " + auth.oAuth2Request.clientId)

                // it wasn't issued to this client
                m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN)
                return JsonErrorView.VIEWNAME
            } else {
                // user and client matched

                resourceSetService.remove(rs)

                m.addAttribute(HttpCodeView.CODE, HttpStatus.NO_CONTENT)
                return HttpCodeView.VIEWNAME
            }
        }
    }

    @RequestMapping(method = [RequestMethod.GET], produces = [MimeTypeUtils.APPLICATION_JSON_VALUE])
    fun listResourceSets(m: Model, auth: Authentication): String {
        ensureOAuthScope(auth, SystemScopeService.UMA_PROTECTION_SCOPE)

        val owner = auth.name

        val resourceSets: Collection<ResourceSet>
        if (auth is OAuth2Authentication) {
            // if it's an OAuth mediated call, it's on behalf of a client, so look that up too
            resourceSets = resourceSetService.getAllForOwnerAndClient(owner, auth.oAuth2Request.clientId)
        } else {
            // otherwise get everything for the current user
            resourceSets = resourceSetService.getAllForOwner(owner)
        }

        // build the entity here and send to the display
        val ids: MutableSet<String> = HashSet()
        for (resourceSet in resourceSets) {
            ids.add(resourceSet.id.toString()) // add them all as strings so that gson renders them properly
        }

        m.addAttribute(JsonEntityView.ENTITY, ids)
        return JsonEntityView.VIEWNAME
    }

    private fun parseResourceSet(jsonString: String): ResourceSet? {
        try {
            val el = parser.parse(jsonString)

            if (el.isJsonObject) {
                val o = el.asJsonObject

                val rs = ResourceSet()
                rs.id = getAsLong(o, "_id")
                rs.name = requireNotNull(getAsString(o, "name")) { "Missing resource name" }
                rs.iconUri = getAsString(o, "icon_uri")
                rs.type = getAsString(o, "type")
                rs.scopes = getAsStringSet(o, "scopes")!!
                rs.uri = getAsString(o, "uri")

                return rs
            }

            return null
        } catch (e: JsonParseException) {
            return null
        }
    }


    /**
     * Make sure the resource set doesn't have any restricted or reserved scopes.
     */
    private fun validateScopes(rs: ResourceSet): ResourceSet {
        // scopes that the client is asking for
        val requestedScopes = scopeService.fromStrings(rs.scopes)

        // the scopes that the resource set can have must be a subset of the dynamically allowed scopes
        val allowedScopes = scopeService.removeRestrictedAndReservedScopes(requestedScopes!!)

        rs.scopes = scopeService.toStrings(allowedScopes)!!

        return rs
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(ResourceSetRegistrationEndpoint::class.java)

        const val DISCOVERY_URL: String = "resource_set"
        const val URL: String = DISCOVERY_URL + "/resource_set"
    }
}
