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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.JSONObjectUtils
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.exception.OAuthErrorCodes.*
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.RegisteredClientFields.APPLICATION_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.CLAIMS_REDIRECT_URIS
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID_ISSUED_AT
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_NAME
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_SECRET
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_SECRET_EXPIRES_AT
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_URI
import org.mitre.oauth2.model.RegisteredClientFields.CONTACTS
import org.mitre.oauth2.model.RegisteredClientFields.DEFAULT_ACR_VALUES
import org.mitre.oauth2.model.RegisteredClientFields.DEFAULT_MAX_AGE
import org.mitre.oauth2.model.RegisteredClientFields.GRANT_TYPES
import org.mitre.oauth2.model.RegisteredClientFields.ID_TOKEN_ENCRYPTED_RESPONSE_ALG
import org.mitre.oauth2.model.RegisteredClientFields.ID_TOKEN_ENCRYPTED_RESPONSE_ENC
import org.mitre.oauth2.model.RegisteredClientFields.ID_TOKEN_SIGNED_RESPONSE_ALG
import org.mitre.oauth2.model.RegisteredClientFields.INITIATE_LOGIN_URI
import org.mitre.oauth2.model.RegisteredClientFields.JWKS
import org.mitre.oauth2.model.RegisteredClientFields.JWKS_URI
import org.mitre.oauth2.model.RegisteredClientFields.LOGO_URI
import org.mitre.oauth2.model.RegisteredClientFields.POLICY_URI
import org.mitre.oauth2.model.RegisteredClientFields.POST_LOGOUT_REDIRECT_URIS
import org.mitre.oauth2.model.RegisteredClientFields.REDIRECT_URIS
import org.mitre.oauth2.model.RegisteredClientFields.REGISTRATION_ACCESS_TOKEN
import org.mitre.oauth2.model.RegisteredClientFields.REGISTRATION_CLIENT_URI
import org.mitre.oauth2.model.RegisteredClientFields.REQUEST_OBJECT_SIGNING_ALG
import org.mitre.oauth2.model.RegisteredClientFields.REQUEST_URIS
import org.mitre.oauth2.model.RegisteredClientFields.REQUIRE_AUTH_TIME
import org.mitre.oauth2.model.RegisteredClientFields.RESPONSE_TYPES
import org.mitre.oauth2.model.RegisteredClientFields.SCOPE
import org.mitre.oauth2.model.RegisteredClientFields.SECTOR_IDENTIFIER_URI
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_STATEMENT
import org.mitre.oauth2.model.RegisteredClientFields.SUBJECT_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.TOKEN_ENDPOINT_AUTH_METHOD
import org.mitre.oauth2.model.RegisteredClientFields.TOKEN_ENDPOINT_AUTH_SIGNING_ALG
import org.mitre.oauth2.model.RegisteredClientFields.TOS_URI
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ALG
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ENC
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_SIGNED_RESPONSE_ALG
import org.mitre.openid.connect.view.clientEntityViewForAdmins
import org.mitre.openid.connect.view.clientEntityViewForUsers
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.asBoolean
import org.mitre.util.asBooleanOrNull
import org.mitre.util.getLogger
import org.mitre.util.oidJson
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.assertionValidator
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.clientLogoLoadingService
import org.mitre.web.util.requireUserRole
import java.text.ParseException

/**
 * @author Michael Jett <mjett></mjett>@mitre.org>
 */
//@Controller
//@RequestMapping("/api/clients")
//@PreAuthorize("hasRole('ROLE_USER')")
object ClientAPI: KtorEndpoint {

    override fun Route.addRoutes() {
        authenticate {
            route("/api/clients") {
                get { apiGetAllClients() }
                post { apiAddClient() }
                put("/{id}") { apiUpdateClient() }
                get("/{id}") { apiShowClient()}
            }
        }
    }

//    @Autowired
//    @Qualifier("clientAssertionValidator")
//    private lateinit var assertionValidator: AssertionValidator

    /**
     * Get a list of all clients
     */
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.apiGetAllClients() {
        val auth = requireUserRole()
        val clients = clientDetailsService.allClients

        if (GrantedAuthority.ROLE_ADMIN in auth.authorities) {
            return clientEntityViewForAdmins(clients)
        } else {
            return clientEntityViewForUsers(clients)
        }
    }

    /**
     * Create a new client
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.apiAddClient() {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN)
        val clientBuilder: OAuthClientDetails.Builder

        val rawJson: JsonObject

        try {
            rawJson = oidJson.parseToJsonElement(call.receiveText()).jsonObject
            clientBuilder = oidJson.decodeFromJsonElement<ClientDetailsEntity>(rawJson).builder()
        } catch (e: SerializationException) {
            logger.error("apiAddClient failed due to SerializationException", e)
            return jsonErrorView(INVALID_REQUEST, "Could not save new client. The server encountered a JSON syntax exception. Contact a system administrator for assistance.")
        } catch (e: IllegalStateException) {
            logger.error("apiAddClient failed due to IllegalStateException", e)
            return jsonErrorView(
                SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not save new client. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            )
        } catch (e: org.mitre.openid.connect.exception.ValidationException) {
            logger.error("apiUpdateClient failed due to ValidationException", e)
            return jsonErrorView(
                INVALID_REQUEST,
                "Could not update client. The server encountered a ValidationException."
            )
        }

        // if they leave the client identifier empty, force it to be generated
        if (clientBuilder.clientId.isNullOrEmpty()) clientBuilder.clientId =
            clientDetailsService.generateClientIdString(clientBuilder.build())

        if (clientBuilder.tokenEndpointAuthMethod == null || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.NONE) {
            // we shouldn't have a secret for this client

            clientBuilder.clientSecret = null
        } else if (clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_BASIC || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_POST || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_JWT) {
            // if they've asked for us to generate a client secret (or they left it blank but require one), do so here

            if (rawJson["generateClientSecret"]?.asBooleanOrNull() == true
                || clientBuilder.clientSecret.isNullOrEmpty()
            ) {
                clientBuilder.clientSecret = clientDetailsService.generateClientSecret(clientBuilder)
            }
        } else if (clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.PRIVATE_KEY) {
            if (clientBuilder.jwksUri.isNullOrEmpty() && clientBuilder.jwks == null) {
                logger.error("tried to create client with private key auth but no private key")
                return jsonErrorView(
                    INVALID_REQUEST,
                    "Can not create a client with private key authentication without registering a key via the JWK Set URI or JWK Set Value."
                )
            }

            // otherwise we shouldn't have a secret for this client
            clientBuilder.clientSecret = null
        } else {
            logger.error("unknown auth method")
            return jsonErrorView(SERVER_ERROR, HttpStatusCode.BadRequest, "Unknown auth method requested")
        }

        clientBuilder.isDynamicallyRegistered = false

        try {
            val newClient = clientDetailsService.saveNewClient(clientBuilder.build())

            if (GrantedAuthority.ROLE_ADMIN in auth.authorities) {
                return clientEntityViewForAdmins(newClient)
            } else {
                return clientEntityViewForUsers(newClient)
            }
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to save client: {}", e.message)
            return jsonErrorView(SERVER_ERROR, HttpStatusCode.BadRequest, "Unable to save client: ${e.message}")
        }
    }

    /**
     * Update an existing client
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.apiUpdateClient(
    ) {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN)
        val id = call.parameters["id"]!!.toLong()

        val clientBuilder: Builder

        val rawJson:  JsonObject

        try {
            rawJson = oidJson.parseToJsonElement(call.receiveText()).jsonObject
            // parse the client passed in (from JSON) and fetch the old client from the store
            clientBuilder = oidJson.decodeFromJsonElement<ClientDetailsEntity>(rawJson).builder()
            validateSoftwareStatement(assertionValidator, clientBuilder)
        } catch (e: SerializationException) {
            logger.error("apiUpdateClient failed due to SerializationException", e)
            return jsonErrorView(
                SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not update client. The server encountered a JSON syntax exception. Contact a system administrator for assistance."
            )
        } catch (e: IllegalStateException) {
            logger.error("apiUpdateClient failed due to IllegalStateException", e)
            return jsonErrorView(
                SERVER_ERROR, HttpStatusCode.BadRequest,
                "Could not update client. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance."
            )
        } catch (e: org.mitre.openid.connect.exception.ValidationException) {
            logger.error("apiUpdateClient failed due to ValidationException", e)
            return jsonErrorView(
                INVALID_REQUEST,
                "Could not update client. The server encountered a ValidationException."
            )
        }

        val oldClient = clientDetailsService.getClientById(id) ?: run {
            logger.error("apiUpdateClient failed; client with id $id could not be found.")
            return jsonErrorView(
                INVALID_REQUEST,
                "Could not update client. The requested client with id " + id + "could not be found."
            )
        }

        // if they leave the client identifier empty, force it to be generated
        if (clientBuilder.clientId.isNullOrEmpty()) {
            clientBuilder.clientId = clientDetailsService.generateClientIdString(clientBuilder.build())
        }

        if (clientBuilder.tokenEndpointAuthMethod == null || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.NONE) {
            // we shouldn't have a secret for this client

            clientBuilder.clientSecret = null
        } else if (clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_BASIC || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_POST || clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_JWT) {
            // if they've asked for us to generate a client secret (or they left it blank but require one), do so here

            if (rawJson["generateClientSecret"]?.asBoolean() == true || clientBuilder.clientSecret.isNullOrEmpty()) {
                clientBuilder.clientSecret = clientDetailsService.generateClientSecret(clientBuilder)
            }
        } else if (clientBuilder.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.PRIVATE_KEY) {
            if (clientBuilder.jwksUri.isNullOrEmpty() && clientBuilder.jwks == null) {
                logger.error("tried to create client with private key auth but no private key")
                return jsonErrorView(
                    INVALID_REQUEST,
                    "Can not create a client with private key authentication without registering a key via the JWK Set URI or JWK Set Value."
                )
            }

            // otherwise we shouldn't have a secret for this client
            clientBuilder.clientSecret = null
        } else {
            logger.error("unknown auth method")
            return jsonErrorView(INVALID_REQUEST, HttpStatusCode.BadRequest, "Unknown auth method requested")
        }

        try {
            val newClient = clientDetailsService.updateClient(oldClient, clientBuilder.build())

            if (GrantedAuthority.ROLE_ADMIN in auth.authorities) {
                return clientEntityViewForAdmins(newClient)
            } else {
                return clientEntityViewForUsers(newClient)
            }
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to save client: {}", e.message)
            return jsonErrorView(SERVER_ERROR, HttpStatusCode.BadRequest, "Unable to save client: ${e.message}")
        }
    }

    /**
     * Delete a client
     */
//    @PreAuthorize("hasRole('ROLE_ADMIN')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    suspend fun RoutingContext.apiDeleteClient(id: Long) {
        val auth = requireUserRole(GrantedAuthority.ROLE_ADMIN)
        val id = call.parameters["id"]!!.toLong()

        val client = clientDetailsService.getClientById(id) ?: run {
            logger.error("apiDeleteClient failed; client with id $id could not be found.")
            return jsonErrorView(
                INVALID_REQUEST, HttpStatusCode.NotFound,
                "Could not delete client. The requested client with id $id could not be found."
            )
        }

        clientDetailsService.deleteClient(client)

        return call.respond(HttpStatusCode.OK)
    }


    /**
     * Get an individual client
     */
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.apiShowClient() {
        val auth = requireUserRole()
        val id = call.parameters["id"]!!.toLong()
        val client = clientDetailsService.getClientById(id) ?: run {
            logger.error("apiShowClient failed; client with id $id could not be found.")
            return jsonErrorView(
                INVALID_REQUEST, HttpStatusCode.NotFound,
                "The requested client with id $id could not be found."
            )
        }

        if (GrantedAuthority.ROLE_ADMIN in auth.authorities) {
            return clientEntityViewForAdmins(client)
        } else {
            return clientEntityViewForUsers(client)
        }
    }

    /**
     * Get the logo image for a client
     */
//    @RequestMapping(value = ["/{id}/logo"], method = [RequestMethod.GET], produces = [MediaType.IMAGE_GIF_VALUE, MediaType.IMAGE_JPEG_VALUE, MediaType.IMAGE_PNG_VALUE])
    suspend fun RoutingContext.getClientLogo() {
        val auth = requireUserRole()
        val id = call.parameters["id"]!!.toLong()
        val client = clientDetailsService.getClientById(id) ?: return call.respond(HttpStatusCode.NotFound)
        val logoUri = client.logoUri?.takeUnless { it.isBlank() } ?: return call.respond(HttpStatusCode.NotFound)

        // get the image from cache
        val image = clientLogoLoadingService.getLogo(client) ?: return call.respond(HttpStatusCode.NotFound)

        call.respondBytes(image.data, ContentType.parse(image.contentType))
    }

    @Throws(org.mitre.openid.connect.exception.ValidationException::class)
    private suspend fun RoutingContext.validateSoftwareStatement(assertionValidator: AssertionValidator, clientBuilder: OAuthClientDetails.Builder) {
        val softwareStatement = clientBuilder.softwareStatement
        if (softwareStatement == null) {
            // nothing to see here, carry on
            return
        } else {
            if (assertionValidator.isValid(softwareStatement)) {
                // we have a software statement and its envelope passed all the checks from our validator

                // swap out all of the client's fields for the associated parts of the software statement

                try {
                    val claimSet = softwareStatement.jwtClaimsSet

                    for (claim in claimSet.claims.keys) {
                        when (claim) {
                            SOFTWARE_STATEMENT -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't include another software statement")
                            }
                            CLAIMS_REDIRECT_URIS ->
                                clientBuilder.claimsRedirectUris = claimSet.getStringListClaim(claim).toHashSet()

                            CLIENT_SECRET_EXPIRES_AT -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't include a client secret expiration time")
                            }
                            CLIENT_ID_ISSUED_AT -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't include a client ID issuance time")
                            }
                            REGISTRATION_CLIENT_URI -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't include a client configuration endpoint")
                            }
                            REGISTRATION_ACCESS_TOKEN -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't include a client registration access token")
                            }
                            REQUEST_URIS -> clientBuilder.requestUris = claimSet.getStringListClaim(claim).toHashSet()
                            POST_LOGOUT_REDIRECT_URIS -> clientBuilder.postLogoutRedirectUris =
                                claimSet.getStringListClaim(claim).toHashSet()

                            INITIATE_LOGIN_URI -> clientBuilder.initiateLoginUri = claimSet.getStringClaim(claim)
                            DEFAULT_ACR_VALUES -> clientBuilder.defaultACRvalues = claimSet.getStringListClaim(claim).toHashSet()

                            REQUIRE_AUTH_TIME -> clientBuilder.requireAuthTime = claimSet.getBooleanClaim(claim)
                            DEFAULT_MAX_AGE -> clientBuilder.defaultMaxAge = claimSet.getIntegerClaim(claim)?.toLong()
                            TOKEN_ENDPOINT_AUTH_SIGNING_ALG -> clientBuilder.tokenEndpointAuthSigningAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_ENCRYPTED_RESPONSE_ENC -> clientBuilder.idTokenEncryptedResponseEnc =
                                EncryptionMethod.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_ENCRYPTED_RESPONSE_ALG -> clientBuilder.idTokenEncryptedResponseAlg =
                                JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_SIGNED_RESPONSE_ALG -> clientBuilder.idTokenSignedResponseAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            USERINFO_ENCRYPTED_RESPONSE_ENC -> clientBuilder.userInfoEncryptedResponseEnc =
                                EncryptionMethod.parse(claimSet.getStringClaim(claim))

                            USERINFO_ENCRYPTED_RESPONSE_ALG -> clientBuilder.userInfoEncryptedResponseAlg =
                                JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                            USERINFO_SIGNED_RESPONSE_ALG -> clientBuilder.userInfoSignedResponseAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            REQUEST_OBJECT_SIGNING_ALG -> clientBuilder.requestObjectSigningAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            SUBJECT_TYPE -> clientBuilder.subjectType =
                                OAuthClientDetails.SubjectType.getByValue(claimSet.getStringClaim(claim))

                            SECTOR_IDENTIFIER_URI -> clientBuilder.sectorIdentifierUri = claimSet.getStringClaim(claim)
                            APPLICATION_TYPE -> clientBuilder.applicationType =
                                OAuthClientDetails.AppType.valueOf(claimSet.getStringClaim(claim))

                            JWKS_URI -> clientBuilder.jwksUri = claimSet.getStringClaim(claim)
                            JWKS -> clientBuilder.jwks =
                                JWKSet.parse(JSONObjectUtils.toJSONString(claimSet.getJSONObjectClaim(claim)))

                            POLICY_URI -> clientBuilder.policyUri = claimSet.getStringClaim(claim)
                            RESPONSE_TYPES -> clientBuilder.responseTypes =
                                claimSet.getStringListClaim(claim).toHashSet()

                            GRANT_TYPES -> clientBuilder.authorizedGrantTypes = claimSet.getStringListClaim(claim).toHashSet()
                            SCOPE -> clientBuilder.scope = claimSet.getStringClaim(claim).split(' ').filterNotTo(HashSet()) { it.isBlank() }
                            TOKEN_ENDPOINT_AUTH_METHOD -> clientBuilder.tokenEndpointAuthMethod =
                                OAuthClientDetails.AuthMethod.getByValue(claimSet.getStringClaim(claim))

                            TOS_URI -> clientBuilder.tosUri = claimSet.getStringClaim(claim)
                            CONTACTS -> clientBuilder.contacts = claimSet.getStringListClaim(claim).toHashSet()
                            LOGO_URI -> clientBuilder.logoUri = claimSet.getStringClaim(claim)
                            CLIENT_URI -> clientBuilder.clientUri = claimSet.getStringClaim(claim)
                            CLIENT_NAME -> clientBuilder.clientName = claimSet.getStringClaim(claim)
                            REDIRECT_URIS -> clientBuilder.redirectUris = claimSet.getStringListClaim(claim).toHashSet()

                            CLIENT_SECRET -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't contain client secret")
                            }
                            CLIENT_ID -> {
                                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement can't contain client ID")
                            }

                            else -> logger.warn("Software statement contained unknown field: " + claim + " with value " + claimSet.getClaim(claim))
                        }
                    }
                } catch (e: ParseException) {
                    return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement claims didn't parse")
                }
            } else {
                return jsonErrorView(INVALID_CLIENT_METADATA, "Software statement rejected by validator")
            }
        }
    }

    const val URL: String = RootController.API_URL + "/clients"

    /**
     * Logger for this class
     */
    private val logger = getLogger<ClientAPI>()
}
