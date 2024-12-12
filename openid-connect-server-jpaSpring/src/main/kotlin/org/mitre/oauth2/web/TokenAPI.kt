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

import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.web.RootController
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
 * REST-ish API for managing access tokens (GET/DELETE only)
 * @author Amanda Anganes
 */
@Controller
@RequestMapping("/" + TokenAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class TokenAPI {
    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var oidcTokenService: OIDCTokenService

    @RequestMapping(value = ["/access"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAllAccessTokens(m: ModelMap, p: Principal): String {
        val allTokens = tokenService.getAllAccessTokensForUser(p.name)
        m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = allTokens
        return org.mitre.oauth2.view.TokenApiView.VIEWNAME
    }

    @RequestMapping(value = ["/access/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAccessTokenById(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val token = tokenService.getAccessTokenById(id)

        if (token == null) {
            logger.error("getToken failed; token not found: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested token with id $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (token.authenticationHolder.principalName != p.name) {
            logger.error("getToken failed; token does not belong to principal " + p.name)
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "You do not have permission to view this token"
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = token
            return org.mitre.oauth2.view.TokenApiView.VIEWNAME
        }
    }

    @RequestMapping(value = ["/access/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun deleteAccessTokenById(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val token = tokenService.getAccessTokenById(id)

        if (token == null) {
            logger.error("getToken failed; token not found: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested token with id $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (token.authenticationHolder.principalName != p.name) {
            logger.error("getToken failed; token does not belong to principal " + p.name)
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "You do not have permission to view this token"
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            tokenService.revokeAccessToken(token)

            return HttpCodeView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/client/{clientId}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAccessTokensByClientId(@PathVariable("clientId") clientId: String, m: ModelMap, p: Principal?): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null) {
            val tokens = tokenService.getAccessTokensForClient(client)
            m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = tokens
            return org.mitre.oauth2.view.TokenApiView.VIEWNAME
        } else {
            // client not found
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested client with id $clientId could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/registration/{clientId}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getRegistrationTokenByClientId(@PathVariable("clientId") clientId: String, m: ModelMap, p: Principal?): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null) {
            val token = tokenService.getRegistrationAccessTokenForClient(client)
            if (token != null) {
                m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = token
                return org.mitre.oauth2.view.TokenApiView.VIEWNAME
            } else {
                m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
                m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "No registration token could be found."
                return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
            }
        } else {
            // client not found
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested client with id $clientId could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        }
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/registration/{clientId}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun rotateRegistrationTokenByClientId(
        @PathVariable("clientId") clientId: String,
        m: ModelMap,
        p: Principal?
    ): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null) {
            val token = oidcTokenService.rotateRegistrationAccessTokenForClient(client)
                ?.let { tokenService.saveAccessToken(it) }

            if (token != null) {
                m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = token
                return org.mitre.oauth2.view.TokenApiView.VIEWNAME
            } else {
                m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
                m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "No registration token could be found."
                return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
            }
        } else {
            // client not found
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested client with id $clientId could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        }
    }

    @RequestMapping(value = ["/refresh"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getAllRefreshTokens(m: ModelMap, p: Principal): String {
        val allTokens = tokenService.getAllRefreshTokensForUser(p.name)
        m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = allTokens
        return org.mitre.oauth2.view.TokenApiView.VIEWNAME
    }

    @RequestMapping(value = ["/refresh/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun getRefreshTokenById(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val token = tokenService.getRefreshTokenById(id)

        if (token == null) {
            logger.error("refresh token not found: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested token with id $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (token.authenticationHolder.principalName != p.name) {
            logger.error("refresh token " + id + " does not belong to principal " + p.name)
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "You do not have permission to view this token"
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            m[org.mitre.openid.connect.view.JsonEntityView.ENTITY] = token
            return org.mitre.oauth2.view.TokenApiView.VIEWNAME
        }
    }

    @RequestMapping(value = ["/refresh/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun deleteRefreshTokenById(@PathVariable("id") id: Long, m: ModelMap, p: Principal): String {
        val token = tokenService.getRefreshTokenById(id)

        if (token == null) {
            logger.error("refresh token not found: $id")
            m[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "The requested token with id $id could not be found."
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else if (token.authenticationHolder.principalName != p.name) {
            logger.error("refresh token " + id + " does not belong to principal " + p.name)
            m[HttpCodeView.CODE] = HttpStatus.FORBIDDEN
            m[org.mitre.openid.connect.view.JsonErrorView.ERROR_MESSAGE] = "You do not have permission to view this token"
            return org.mitre.openid.connect.view.JsonErrorView.VIEWNAME
        } else {
            tokenService.revokeRefreshToken(token)

            return HttpCodeView.VIEWNAME
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/tokens"

        /**
         * Logger for this class
         */
        private val logger = getLogger<TokenAPI>()
    }
}
