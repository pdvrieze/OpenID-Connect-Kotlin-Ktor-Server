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
package org.mitre.openid.connect.web

import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.ClientJwtAuthentication
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.SerializationException
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse
import org.mitre.openid.connect.exception.ValidationException
import org.mitre.openid.connect.view.clientInformationResponseView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.oidcTokenService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireClientTokenScope
import org.mitre.web.util.scopeService
import org.mitre.web.util.tokenService
import java.text.ParseException
import java.time.Instant
import java.util.*

object ProtectedResourceRegistrationEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        route("resource") {
            post { registerNewProtectedResource() }
            authenticate {
                get("/{id}") { readResourceConfiguration() }
                put("/{id}") { updateProtectedResource() }
                delete("/{id}") { deleteResource() }
            }
        }
    }


    /**
     * Create a new Client, issue a client ID, and create a registration access token.
     */
//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.registerNewProtectedResource() {
        val newClientBuilder: ClientDetailsEntity.Builder?
        try {
            newClientBuilder = parse(call.receiveText()).builder()
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("registerNewProtectedResource failed; submitted JSON is malformed")
            return call.respond(HttpStatusCode.BadRequest)
        }

        // it parsed!

        //
        // Now do some post-processing consistency checks on it
        //

        // clear out any spurious id/secret (clients don't get to pick)

        newClientBuilder.clientId = null
        newClientBuilder.clientSecret = null

        // do validation on the fields
        try {
            validateScopes(newClientBuilder)
            validateAuth(newClientBuilder)
        } catch (ve: ValidationException) {
            return jsonErrorView(ve)
        }


        // no grant types are allowed
        newClientBuilder.authorizedGrantTypes = HashSet()
        newClientBuilder.responseTypes = HashSet()
        newClientBuilder.redirectUris = HashSet()

        // don't issue tokens to this client
        newClientBuilder.accessTokenValiditySeconds = 0
        newClientBuilder.idTokenValiditySeconds = 0
        newClientBuilder.refreshTokenValiditySeconds = 0

        // clear out unused fields
        newClientBuilder.defaultACRvalues = HashSet()
        newClientBuilder.defaultMaxAge = null
        newClientBuilder.idTokenEncryptedResponseAlg = null
        newClientBuilder.idTokenEncryptedResponseEnc = null
        newClientBuilder.idTokenSignedResponseAlg = null
        newClientBuilder.initiateLoginUri = null
        newClientBuilder.postLogoutRedirectUris = null
        newClientBuilder.requestObjectSigningAlg = null
        newClientBuilder.requireAuthTime = null
        newClientBuilder.isReuseRefreshToken = false
        newClientBuilder.sectorIdentifierUri = null
        newClientBuilder.subjectType = null
        newClientBuilder.userInfoEncryptedResponseAlg = null
        newClientBuilder.userInfoEncryptedResponseEnc = null
        newClientBuilder.userInfoSignedResponseAlg = null

        // this client has been dynamically registered (obviously)
        newClientBuilder.isDynamicallyRegistered = true

        // this client has access to the introspection endpoint
        newClientBuilder.isAllowIntrospection = true

        // now save it
        try {
            val savedClient = clientDetailsService.saveNewClient(newClientBuilder.build())

            // generate the registration access token
            val token = oidcTokenService.createResourceAccessToken(savedClient)!!
            tokenService.saveAccessToken(token)

            // send it all out to the view
            val registered = RegisteredClient(savedClient, token.value, clientRegistrationUri(savedClient))
            return clientInformationResponseView(registered, HttpStatusCode.Created)
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)
            return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT_METADATA, "Unable to save client due to invalid or inconsistent metadata.")
        }
    }

    @Throws(ValidationException::class)
    private suspend fun RoutingContext.validateScopes(newClient: ClientDetailsEntity.Builder) {
        val scopeService = scopeService
        // scopes that the client is asking for
        val requestedScopes = scopeService.fromStrings(newClient.scope)!!

        // the scopes that the client can have must be a subset of the dynamically allowed scopes
        var allowedScopes: Set<SystemScope>? = scopeService.removeRestrictedAndReservedScopes(requestedScopes)

        // if the client didn't ask for any, give them the defaults
        if (allowedScopes.isNullOrEmpty()) {
            allowedScopes = scopeService.defaults
        }

        newClient.scope = scopeService.toStrings(allowedScopes)?.toHashSet() ?: hashSetOf()
    }

    /**
     * Get the meta information for a client.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    private suspend fun RoutingContext.readResourceConfiguration() {
        val auth = requireClientTokenScope(SystemScopeService.RESOURCE_TOKEN_SCOPE).getOrElse { return }
        val client = clientDetailsService.loadClientByClientId(call.parameters["id"]!!)

        if (client == null || client.clientId != auth.clientId) {
            // client mismatch
            logger.error("readResourceConfiguration failed, client ID mismatch: ${call.parameters["id"]} and ${auth.clientId} do not match.")

            return call.respond(HttpStatusCode.Forbidden)
        }

        // possibly update the token
        val token = fetchValidRegistrationToken(auth, client)

        val registered = RegisteredClient(client, token.value, clientRegistrationUri(client))
        return clientInformationResponseView(registered, HttpStatusCode.OK)
    }

    /**
     * Update the metainformation for a given client.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.updateProtectedResource() {
        val auth = requireClientTokenScope(SystemScopeService.RESOURCE_TOKEN_SCOPE).getOrElse { return }
        val clientId = call.parameters["id"]!!

        val newClient: ClientDetailsEntity.Builder?
        try {
            newClient = parse(call.receiveText()).builder()
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("updateProtectedResource failed; submitted JSON is malformed")
            return call.respond(HttpStatusCode.BadRequest)
        }

        val oldClient = clientDetailsService.loadClientByClientId(clientId)

        if (oldClient?.clientId != auth.clientId || oldClient.clientId != newClient.clientId) {
            // client mismatch
            logger.error("updateProtectedResource failed, client ID mismatch: $clientId and ${auth.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }

        // we have an existing client and the new one parsed
        // a client can't ask to update its own client secret to any particular value

        newClient.clientSecret = oldClient.clientSecret

        newClient.createdAt = oldClient.createdAt

        // no grant types are allowed
        newClient.authorizedGrantTypes = HashSet()
        newClient.responseTypes = HashSet()
        newClient.redirectUris = HashSet()

        // don't issue tokens to this client
        newClient.accessTokenValiditySeconds = 0
        newClient.idTokenValiditySeconds = 0
        newClient.refreshTokenValiditySeconds = 0

        // clear out unused fields
        newClient.defaultACRvalues = HashSet()
        newClient.defaultMaxAge = null
        newClient.idTokenEncryptedResponseAlg = null
        newClient.idTokenEncryptedResponseEnc = null
        newClient.idTokenSignedResponseAlg = null
        newClient.initiateLoginUri = null
        newClient.postLogoutRedirectUris = null
        newClient.requestObjectSigningAlg = null
        newClient.requireAuthTime = null
        newClient.isReuseRefreshToken = false
        newClient.sectorIdentifierUri = null
        newClient.subjectType = null
        newClient.userInfoEncryptedResponseAlg = null
        newClient.userInfoEncryptedResponseEnc = null
        newClient.userInfoSignedResponseAlg = null

        // this client has been dynamically registered (obviously)
        newClient.isDynamicallyRegistered = true

        // this client has access to the introspection endpoint
        newClient.isAllowIntrospection = true

        // do validation on the fields
        try {
            validateScopes(newClient)
            validateAuth(newClient)
        } catch (ve: ValidationException) {
            return call.respond(ve)
        }


        try {
            // save the client
            val savedClient = clientDetailsService.updateClient(oldClient, newClient.build())

            // possibly update the token
            val token = fetchValidRegistrationToken(auth, savedClient)

            val registered = RegisteredClient(savedClient, token.value, clientRegistrationUri(savedClient))

            return clientInformationResponseView(registered)
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)
            return jsonErrorView(OAuthErrorCodes.INVALID_CLIENT_METADATA, "Unable to save client due to invalid or inconsistent metadata.")
        }
    }

    /**
     * Delete the indicated client from the system.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.deleteResource() {
        val auth = requireClientTokenScope(SystemScopeService.RESOURCE_TOKEN_SCOPE).getOrElse { return }
        val clientId = call.parameters["id"]!!
        val client = clientDetailsService.loadClientByClientId(clientId)

        if (client == null) {
            // client mismatch
            logger.error("readClientConfiguration failed, client ID mismatch: $clientId and ${auth.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }

        if (client.clientId != auth.clientId) {
            // client mismatch
            logger.error("readClientConfiguration failed, client ID mismatch: $clientId and ${auth.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }

        clientDetailsService.deleteClient(client)
        return call.respond(HttpStatusCode.NoContent)
    }

    @Throws(ValidationException::class)
    private suspend fun RoutingContext.validateAuth(newClient: ClientDetailsEntity.Builder) {
        if (newClient.tokenEndpointAuthMethod == null) {
            newClient.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        when (newClient.tokenEndpointAuthMethod) {
            AuthMethod.SECRET_BASIC, AuthMethod.SECRET_JWT, AuthMethod.SECRET_POST -> {
                if (newClient.clientSecret.isNullOrEmpty()) {
                    // no secret yet, we need to generate a secret
                    newClient.clientSecret = clientDetailsService.generateClientSecret(newClient)
                }
            }

            AuthMethod.PRIVATE_KEY -> {
                if (newClient.jwksUri.isNullOrEmpty() && newClient.jwks == null) {
                    throw ValidationException(OAuthErrorCodes.INVALID_CLIENT_METADATA, "JWK Set URI required when using private key authentication")
                }

                newClient.clientSecret = null
            }

            AuthMethod.NONE -> newClient.clientSecret = null

            else ->
                throw ValidationException(OAuthErrorCodes.INVALID_CLIENT_METADATA, "Unknown authentication method")
        }
    }

    private suspend fun RoutingContext.fetchValidRegistrationToken(
        auth: ClientAuthentication,
        client: OAuthClientDetails
    ): OAuth2AccessTokenEntity {
        val config = openIdContext.config
        if (auth !is ClientJwtAuthentication) { call.respond(HttpStatusCode.Unauthorized); error("unreachable") }
        val token = tokenService.readAccessToken(auth.token)

        val regTokenLifeTime = config.regTokenLifeTime
        if (regTokenLifeTime != null) {
            try {
                // Re-issue the token if it has been issued before [currentTime - validity]
                val validToDate = Date(Instant.now().epochSecond - regTokenLifeTime)
                if (token.jwt.jwtClaimsSet.issueTime.before(validToDate)) {
                    logger.info("Rotating the registration access token for " + client.clientId)
                    tokenService.revokeAccessToken(token)
                    val newToken = oidcTokenService.createResourceAccessToken(client)
                    tokenService.saveAccessToken(newToken!!)
                    return newToken
                } else {
                    // it's not expired, keep going
                    return token
                }
            } catch (e: ParseException) {
                logger.error("Couldn't parse a known-valid token?", e)
                return token
            }
        } else {
            // tokens don't expire, just return it
            return token
        }
    }

    const val URL: String = "resource"

    /**
     * Logger for this class
     */
    private val logger = getLogger<ProtectedResourceRegistrationEndpoint>()
}
