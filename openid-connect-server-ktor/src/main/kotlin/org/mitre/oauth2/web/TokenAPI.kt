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

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.encodeToJsonElement
import org.mitre.oauth2.exception.OAuthErrorCodes.*
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.view.respondJson
import org.mitre.oauth2.view.tokenApiView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientService
import org.mitre.web.util.oidcTokenService
import org.mitre.web.util.requireRole
import org.mitre.web.util.tokenService

/**
 * REST-ish API for managing access tokens (GET/DELETE only)
 * @author Amanda Anganes
 */
//@Controller
//@RequestMapping("/" + TokenAPI.URL)
//@PreAuthorize("hasRole('ROLE_USER')")
object TokenAPI : KtorEndpoint {
    override fun Route.addRoutes() {
        route("/api/tokens") {
            authenticate {
                get("/access") { getAllAccessTokens() }
                get("/access/{id}") { getAccessTokenById() }
                delete("/access/{id}") { deleteAccessTokenById() }
                get("/client/{clientId}") { getAccessTokensByClientId() }

                get("/registration/{clientId}") { getRegistrationTokenByClientId() }
                put("/registration/{clientId}") { rotateRegistrationTokenByClientId() }

                get("/refresh") { getAllRefreshTokens() }
                get("/refresh/{id}") { getRefreshTokenById() }
                delete("/refresh/{id}") { deleteRefreshTokenById() }
            }
        }
    }

    //    @RequestMapping(value = ["/access"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAllAccessTokens() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }

        return call.respondJson(tokenService.getAllAccessTokensForUser(p.name).map { it.serialDelegate() })
    }

    //    @RequestMapping(value = ["/access/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAccessTokenById() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }

        val id = call.parameters["id"]!!.toLong()
        val token = tokenService.getAccessTokenById(id)

        if (token == null) {
            logger.error("getToken failed; token not found: $id")
            return jsonErrorView(INVALID_TOKEN, HttpStatusCode.NotFound, "The requested token with id $id could not be found.")
        } else if (token.authenticationHolder.authentication.name != p.name) {
            logger.error("getToken failed; token does not belong to principal " + p.name)
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to view this token")
        } else {
            return tokenApiView(json.encodeToJsonElement(token))
        }
    }

    //    @RequestMapping(value = ["/access/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.deleteAccessTokenById() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }
        val id = call.parameters["id"]!!.toLong()
        val token = tokenService.getAccessTokenById(id)

        if (token == null) {
            logger.error("getToken failed; token not found: $id")
            return jsonErrorView(INVALID_TOKEN, HttpStatusCode.NotFound, "The requested token with id $id could not be found.")
        } else if (token.authenticationHolder.authentication.name != p.name) {
            logger.error("getToken failed; token does not belong to principal " + p.name)
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to delete this token")
        } else {
            tokenService.revokeAccessToken(token)
            return call.response.status(HttpStatusCode.OK)
        }
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/client/{clientId}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAccessTokensByClientId() {
        requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val clientId = call.parameters["clientId"]!!
        val client = clientService.loadClientByClientId(clientId)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "The requested client with id $clientId could not be found.")

        val tokens = tokenService.getAccessTokensForClient(client)
        return tokenApiView(json.encodeToJsonElement(tokens))
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/registration/{clientId}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getRegistrationTokenByClientId() {
        requireRole(GrantedAuthority.ROLE_USER) { return }
        val clientId = call.parameters["clientId"]!!
        val client = clientService.loadClientByClientId(clientId)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "The requested client with id $clientId could not be found.")

        val token = tokenService.getRegistrationAccessTokenForClient(client)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "No registration token could be found.")

        return call.respondJson(token)
    }

    //    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/registration/{clientId}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.rotateRegistrationTokenByClientId() {
        val p = requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val clientId = call.parameters["clientId"]!!

        val client = clientService.loadClientByClientId(clientId)
            ?: return jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "The requested client with id $clientId could not be found.")

        val token = oidcTokenService.rotateRegistrationAccessTokenForClient(client)
            ?.let { tokenService.saveAccessToken(it) }
            ?: jsonErrorView(INVALID_REQUEST, HttpStatusCode.NotFound, "No registration token could be found.")

        return tokenApiView(json.encodeToJsonElement(token))
    }

    //    @RequestMapping(value = ["/refresh"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getAllRefreshTokens() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }
        val allTokens = tokenService.getAllRefreshTokensForUser(p.name).map { it.serialDelegate() }
        return tokenApiView(json.encodeToJsonElement(allTokens))
    }

    //    @RequestMapping(value = ["/refresh/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.getRefreshTokenById() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }
        val id = call.parameters["id"]!!.toLong()
        val token = tokenService.getRefreshTokenById(id)
            ?: run {
                logger.error("refresh token not found: $id")
                return jsonErrorView(INVALID_TOKEN, HttpStatusCode.NotFound, "The requested token with id $id could not be found.")
            }

        if (token.authenticationHolder.authentication.name != p.name) {
            logger.error("refresh token $id does not belong to principal ${p.name}")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to view this token")
        }

        return tokenApiView(json.encodeToJsonElement(token))
    }

    //    @RequestMapping(value = ["/refresh/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.deleteRefreshTokenById() {
        val p = requireRole(GrantedAuthority.ROLE_USER) { return }

        val id = call.parameters["id"]!!.toLong()
        val token = tokenService.getRefreshTokenById(id)
            ?: run {
                logger.error("refresh token not found: $id")
                return jsonErrorView(INVALID_TOKEN, HttpStatusCode.NotFound, "The requested token with id $id could not be found.")
            }

        if (token.authenticationHolder.authentication.name != p.name) {
            logger.error("refresh token $id does not belong to principal ${p.name}")
            return jsonErrorView(ACCESS_DENIED, "You do not have permission to view this token")
        }


        tokenService.revokeRefreshToken(token)

        return call.respond(HttpStatusCode.OK)
    }

    const val URL: String = "api/tokens"

    /**
     * Logger for this class
     */
    private val logger = getLogger<TokenAPI>()
}
