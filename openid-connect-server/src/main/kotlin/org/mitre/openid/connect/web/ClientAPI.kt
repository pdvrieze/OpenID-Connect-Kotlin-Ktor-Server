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
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.eclipse.persistence.exceptions.DatabaseException
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.model.ClientDetailsEntity.*
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
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.web.AuthenticationUtilities
import org.mitre.openid.connect.exception.ValidationException
import org.mitre.openid.connect.service.ClientLogoLoadingService
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.view.ClientEntityViewForAdmins
import org.mitre.openid.connect.view.ClientEntityViewForUsers
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.util.asBoolean
import org.mitre.util.asBooleanOrNull
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.servlet.ModelAndView
import java.sql.SQLIntegrityConstraintViolationException
import java.text.ParseException
import javax.persistence.PersistenceException

/**
 * @author Michael Jett <mjett></mjett>@mitre.org>
 */
@Controller
@RequestMapping("/" + ClientAPI.URL)
@PreAuthorize("hasRole('ROLE_USER')")
class ClientAPI {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var clientLogoLoadingService: ClientLogoLoadingService

    @Autowired
    @Qualifier("clientAssertionValidator")
    private lateinit var assertionValidator: AssertionValidator

    /**
     * Get a list of all clients
     */
    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun apiGetAllClients(model: Model, auth: Authentication): String {
        val clients = clientService.allClients
        model.addAttribute(JsonEntityView.ENTITY, clients)

        return if (AuthenticationUtilities.isAdmin(auth)) {
            ClientEntityViewForAdmins.VIEWNAME
        } else {
            ClientEntityViewForUsers.VIEWNAME
        }
    }

    /**
     * Create a new client
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun apiAddClient(@RequestBody jsonString: String, m: Model, auth: Authentication): String {
        val json: JsonObject = MITREidDataService.json.parseToJsonElement(jsonString).jsonObject
        var client: OAuthClientDetails

        try {
            client = MITREidDataService.json.decodeFromJsonElement(json)
        } catch (e: SerializationException) {
            logger.error("apiAddClient failed due to SerializationException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not save new client. The server encountered a JSON syntax exception. Contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("apiAddClient failed due to IllegalStateException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not save new client. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        } catch (e: ValidationException) {
            logger.error("apiUpdateClient failed due to ValidationException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not update client. The server encountered a ValidationException.")
            return JsonErrorView.VIEWNAME
        }

        // if they leave the client identifier empty, force it to be generated
        if (client.getClientId().isNullOrEmpty()) client =
            client.copy(clientId = clientService.generateClientIdString(client))

        if (client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.NONE) {
            // we shouldn't have a secret for this client

            client.copy(clientSecret = null)
        } else if (client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_BASIC || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_POST || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_JWT) {
            // if they've asked for us to generate a client secret (or they left it blank but require one), do so here

            if (json["generateClientSecret"]?.asBooleanOrNull() == true
                || client.getClientSecret().isNullOrEmpty()
            ) {
                client = client.copy(clientSecret = clientService.generateClientSecret(client))
            }
        } else if (client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.PRIVATE_KEY) {
            if (client.jwksUri.isNullOrEmpty() && client.jwks == null) {
                logger.error("tried to create client with private key auth but no private key")
                m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
                m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Can not create a client with private key authentication without registering a key via the JWK Set URI or JWK Set Value.")
                return JsonErrorView.VIEWNAME
            }

            // otherwise we shouldn't have a secret for this client
            client = client.copy(clientSecret = null)
        } else {
            logger.error("unknown auth method")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unknown auth method requested")
            return JsonErrorView.VIEWNAME
        }

        client = client.copy(isDynamicallyRegistered = false)

        try {
            val newClient = clientService.saveNewClient(client)
            m.addAttribute(JsonEntityView.ENTITY, newClient)

            return if (AuthenticationUtilities.isAdmin(auth)) {
                ClientEntityViewForAdmins.VIEWNAME
            } else {
                ClientEntityViewForUsers.VIEWNAME
            }
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to save client: {}", e.message)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unable to save client: " + e.message)
            return JsonErrorView.VIEWNAME
        } catch (e: PersistenceException) {
            val cause = e.cause
            if (cause is DatabaseException) {
                val databaseExceptionCause = cause.cause
                if (databaseExceptionCause is SQLIntegrityConstraintViolationException) {
                    logger.error("apiAddClient failed; duplicate client id entry found: {}", client.getClientId())
                    m.addAttribute(HttpCodeView.CODE, HttpStatus.CONFLICT)
                    m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unable to save client. Duplicate client id entry found: " + client.getClientId())
                    return JsonErrorView.VIEWNAME
                }
            }
            throw e
        }
    }

    /**
     * Update an existing client
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun apiUpdateClient(
        @PathVariable("id") id: Long,
        @RequestBody jsonString: String,
        m: Model,
        auth: Authentication
    ): String {
        val json: JsonObject
        var client: OAuthClientDetails

        try {
            json = Json.parseToJsonElement(jsonString).jsonObject
            // parse the client passed in (from JSON) and fetch the old client from the store
            client = Json.decodeFromJsonElement(json)
            client = validateSoftwareStatement(client)
        } catch (e: SerializationException) {
            logger.error("apiUpdateClient failed due to SerializationException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not update client. The server encountered a JSON syntax exception. Contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        } catch (e: IllegalStateException) {
            logger.error("apiUpdateClient failed due to IllegalStateException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not update client. The server encountered an IllegalStateException. Refresh and try again - if the problem persists, contact a system administrator for assistance.")
            return JsonErrorView.VIEWNAME
        } catch (e: ValidationException) {
            logger.error("apiUpdateClient failed due to ValidationException", e)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not update client. The server encountered a ValidationException.")
            return JsonErrorView.VIEWNAME
        }

        val oldClient = clientService.getClientById(id)

        if (oldClient == null) {
            logger.error("apiUpdateClient failed; client with id $id could not be found.")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Could not update client. The requested client with id " + id + "could not be found.")
            return JsonErrorView.VIEWNAME
        }

        // if they leave the client identifier empty, force it to be generated
        if (client.getClientId().isNullOrEmpty()) {
            client = client.copy(clientId = clientService.generateClientIdString(client))
        }

        if (client.tokenEndpointAuthMethod == null || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.NONE) {
            // we shouldn't have a secret for this client

            client.copy(clientSecret = null)
        } else if (client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_BASIC || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_POST || client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.SECRET_JWT) {
            // if they've asked for us to generate a client secret (or they left it blank but require one), do so here

            if (json["generateClientSecret"]?.asBoolean() == true || client.getClientSecret().isNullOrEmpty()) {
                client = client.copy(clientSecret = clientService.generateClientSecret(client))
            }
        } else if (client.tokenEndpointAuthMethod == OAuthClientDetails.AuthMethod.PRIVATE_KEY) {
            if (client.jwksUri.isNullOrEmpty() && client.jwks == null) {
                logger.error("tried to create client with private key auth but no private key")
                m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
                m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Can not create a client with private key authentication without registering a key via the JWK Set URI or JWK Set Value.")
                return JsonErrorView.VIEWNAME
            }

            // otherwise we shouldn't have a secret for this client
            client = client.copy(clientSecret = null)
        } else {
            logger.error("unknown auth method")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unknown auth method requested")
            return JsonErrorView.VIEWNAME
        }

        try {
            val newClient = clientService.updateClient(oldClient, client)
            m.addAttribute(JsonEntityView.ENTITY, newClient)

            return if (AuthenticationUtilities.isAdmin(auth)) {
                ClientEntityViewForAdmins.VIEWNAME
            } else {
                ClientEntityViewForUsers.VIEWNAME
            }
        } catch (e: IllegalArgumentException) {
            logger.error("Unable to save client: {}", e.message)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unable to save client: " + e.message)
            return JsonErrorView.VIEWNAME
        }
    }

    /**
     * Delete a client
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE])
    fun apiDeleteClient(@PathVariable("id") id: Long, modelAndView: ModelAndView): String {
        val client = clientService.getClientById(id)

        if (client == null) {
            logger.error("apiDeleteClient failed; client with id $id could not be found.")
            modelAndView.modelMap[HttpCodeView.CODE] = HttpStatus.NOT_FOUND
            modelAndView.modelMap[JsonErrorView.ERROR_MESSAGE] =
                "Could not delete client. The requested client with id " + id + "could not be found."
            return JsonErrorView.VIEWNAME
        } else {
            modelAndView.modelMap[HttpCodeView.CODE] = HttpStatus.OK
            clientService.deleteClient(client)
        }

        return HttpCodeView.VIEWNAME
    }


    /**
     * Get an individual client
     */
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun apiShowClient(@PathVariable("id") id: Long, model: Model, auth: Authentication): String {
        val client = clientService.getClientById(id)

        if (client == null) {
            logger.error("apiShowClient failed; client with id $id could not be found.")
            model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND)
            model.addAttribute(JsonErrorView.ERROR_MESSAGE, "The requested client with id $id could not be found.")
            return JsonErrorView.VIEWNAME
        }

        model.addAttribute(JsonEntityView.ENTITY, client)

        return if (AuthenticationUtilities.isAdmin(auth)) {
            ClientEntityViewForAdmins.VIEWNAME
        } else {
            ClientEntityViewForUsers.VIEWNAME
        }
    }

    /**
     * Get the logo image for a client
     */
    @RequestMapping(value = ["/{id}/logo"], method = [RequestMethod.GET], produces = [MediaType.IMAGE_GIF_VALUE, MediaType.IMAGE_JPEG_VALUE, MediaType.IMAGE_PNG_VALUE])
    fun getClientLogo(@PathVariable("id") id: Long, model: Model?): ResponseEntity<ByteArray?> {
        val client = clientService.getClientById(id)

        if (client == null) {
            return ResponseEntity(HttpStatus.NOT_FOUND)
        } else if (client.logoUri.isNullOrEmpty()) {
            return ResponseEntity(HttpStatus.NOT_FOUND)
        } else {
            // get the image from cache
            val image = clientLogoLoadingService.getLogo(client)
                ?: return ResponseEntity(HttpStatus.NOT_FOUND)

            val headers = HttpHeaders()
            headers.contentType = MediaType.parseMediaType(image.contentType!!)
            headers.contentLength = image.length

            return ResponseEntity(image.data, headers, HttpStatus.OK)
        }
    }

    @Throws(ValidationException::class)
    private fun validateSoftwareStatement(newClient: OAuthClientDetails): OAuthClientDetails {
        val softwareStatement = newClient.softwareStatement
        if (softwareStatement == null) {
            // nothing to see here, carry on
            return newClient
        } else {
            if (assertionValidator.isValid(softwareStatement)) {
                // we have a software statement and its envelope passed all the checks from our validator

                // swap out all of the client's fields for the associated parts of the software statement

                try {
                    val claimSet = softwareStatement.jwtClaimsSet

                    var newClaimsRedirectUris: Set<String>? = newClient.claimsRedirectUris
                    var newRequestUris: Set<String>? = newClient.requestUris
                    var newPostLogoutRedirectUris: Set<String>? = newClient.postLogoutRedirectUris
                    var newInitiateLoginUri: String? = newClient.initiateLoginUri
                    var newDefaultACRvalues: Set<String>? = newClient.defaultACRvalues
                    var newRequireAuthTime: Boolean? = newClient.requireAuthTime
                    var newDefaultMaxAge: Long? = newClient.defaultMaxAge
                    var newTokenEndpointAuthSigningAlg: JWSAlgorithm? = newClient.tokenEndpointAuthSigningAlg
                    var newIdTokenEncryptedResponseEnc: EncryptionMethod? = newClient.idTokenEncryptedResponseEnc
                    var newIdTokenEncryptedResponseAlg: JWEAlgorithm? = newClient.idTokenEncryptedResponseAlg
                    var newIdTokenSignedResponseAlg: JWSAlgorithm? = newClient.idTokenSignedResponseAlg
                    var newUserInfoEncryptedResponseEnc: EncryptionMethod? = newClient.userInfoEncryptedResponseEnc
                    var newUserInfoEncryptedResponseAlg: JWEAlgorithm? = newClient.userInfoEncryptedResponseAlg
                    var newUserInfoSignedResponseAlg: JWSAlgorithm? = newClient.userInfoSignedResponseAlg
                    var newRequestObjectSigningAlg: JWSAlgorithm? = newClient.requestObjectSigningAlg
                    var newSubjectType: OAuthClientDetails.SubjectType? = newClient.subjectType
                    var newSectorIdentifierUri: String? = newClient.sectorIdentifierUri
                    var newApplicationType: OAuthClientDetails.AppType = newClient.applicationType
                    var newJwksUri: String? = newClient.jwksUri
                    var newJwks: JWKSet? = newClient.jwks
                    var newPolicyUri: String? = newClient.policyUri
                    var newResponseTypes: Set<String> = newClient.responseTypes
                    var newGrantTypes: Set<String> = newClient.grantTypes
                    var newScopes: Set<String> = newClient.getScope()
                    var newTokenEndpointAuthMethod: OAuthClientDetails.AuthMethod? = newClient.tokenEndpointAuthMethod
                    var newTosUri: String? = newClient.tosUri
                    var newContacts: Set<String>? = newClient.contacts
                    var newLogoUri: String? = newClient.logoUri
                    var newClientUri: String? = newClient.clientUri
                    var newClientName: String? = newClient.clientName
                    var newRedirectUris: Set<String> = newClient.redirectUris

                    for (claim in claimSet.claims.keys) {
                        when (claim) {
                            SOFTWARE_STATEMENT -> throw ValidationException("invalid_client_metadata", "Software statement can't include another software statement", HttpStatus.BAD_REQUEST)
                            CLAIMS_REDIRECT_URIS -> newClaimsRedirectUris =
                                claimSet.getStringListClaim(claim).toHashSet()

                            CLIENT_SECRET_EXPIRES_AT -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client secret expiration time", HttpStatus.BAD_REQUEST)
                            CLIENT_ID_ISSUED_AT -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client ID issuance time", HttpStatus.BAD_REQUEST)
                            REGISTRATION_CLIENT_URI -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client configuration endpoint", HttpStatus.BAD_REQUEST)
                            REGISTRATION_ACCESS_TOKEN -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client registration access token", HttpStatus.BAD_REQUEST)
                            REQUEST_URIS -> newRequestUris = claimSet.getStringListClaim(claim).toHashSet()
                            POST_LOGOUT_REDIRECT_URIS -> newPostLogoutRedirectUris =
                                claimSet.getStringListClaim(claim).toHashSet()

                            INITIATE_LOGIN_URI -> newInitiateLoginUri = claimSet.getStringClaim(claim)
                            DEFAULT_ACR_VALUES -> newDefaultACRvalues =
                                claimSet.getStringListClaim(claim).toHashSet()

                            REQUIRE_AUTH_TIME -> newRequireAuthTime = claimSet.getBooleanClaim(claim)
                            DEFAULT_MAX_AGE -> newDefaultMaxAge = claimSet.getIntegerClaim(claim)?.toLong()
                            TOKEN_ENDPOINT_AUTH_SIGNING_ALG -> newTokenEndpointAuthSigningAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_ENCRYPTED_RESPONSE_ENC -> newIdTokenEncryptedResponseEnc =
                                EncryptionMethod.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_ENCRYPTED_RESPONSE_ALG -> newIdTokenEncryptedResponseAlg =
                                JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                            ID_TOKEN_SIGNED_RESPONSE_ALG -> newIdTokenSignedResponseAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            USERINFO_ENCRYPTED_RESPONSE_ENC -> newUserInfoEncryptedResponseEnc =
                                EncryptionMethod.parse(claimSet.getStringClaim(claim))

                            USERINFO_ENCRYPTED_RESPONSE_ALG -> newUserInfoEncryptedResponseAlg =
                                JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                            USERINFO_SIGNED_RESPONSE_ALG -> newUserInfoSignedResponseAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            REQUEST_OBJECT_SIGNING_ALG -> newRequestObjectSigningAlg =
                                JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                            SUBJECT_TYPE -> newSubjectType =
                                OAuthClientDetails.SubjectType.getByValue(claimSet.getStringClaim(claim))

                            SECTOR_IDENTIFIER_URI -> newSectorIdentifierUri = claimSet.getStringClaim(claim)
                            APPLICATION_TYPE -> newApplicationType =
                                OAuthClientDetails.AppType.valueOf(claimSet.getStringClaim(claim))

                            JWKS_URI -> newJwksUri = claimSet.getStringClaim(claim)
                            JWKS -> newJwks = JWKSet.parse(JSONObjectUtils.toJSONString(claimSet.getJSONObjectClaim(claim)))
                            POLICY_URI -> newPolicyUri = claimSet.getStringClaim(claim)
                            RESPONSE_TYPES -> newResponseTypes =
                                claimSet.getStringListClaim(claim).toHashSet()

                            GRANT_TYPES -> newGrantTypes = claimSet.getStringListClaim(claim).toHashSet()
                            SCOPE -> newScopes = OAuth2Utils.parseParameterList(claimSet.getStringClaim(claim))
                            TOKEN_ENDPOINT_AUTH_METHOD -> newTokenEndpointAuthMethod =
                                OAuthClientDetails.AuthMethod.getByValue(claimSet.getStringClaim(claim))

                            TOS_URI -> newTosUri = claimSet.getStringClaim(claim)
                            CONTACTS -> newContacts = claimSet.getStringListClaim(claim).toHashSet()
                            LOGO_URI -> newLogoUri = claimSet.getStringClaim(claim)
                            CLIENT_URI -> newClientUri = claimSet.getStringClaim(claim)
                            CLIENT_NAME -> newClientName = claimSet.getStringClaim(claim)
                            REDIRECT_URIS -> newRedirectUris = claimSet.getStringListClaim(claim).toHashSet()

                            CLIENT_SECRET -> throw ValidationException("invalid_client_metadata", "Software statement can't contain client secret", HttpStatus.BAD_REQUEST)
                            CLIENT_ID -> throw ValidationException("invalid_client_metadata", "Software statement can't contain client ID", HttpStatus.BAD_REQUEST)

                            else -> logger.warn("Software statement contained unknown field: " + claim + " with value " + claimSet.getClaim(claim))
                        }
                    }

                    val updatedClient = newClient.copy(
                        redirectUris = newRedirectUris,
                        clientName = newClientName,
                        clientUri = newClientUri,
                        logoUri = newLogoUri,
                        contacts = newContacts,
                        tosUri = newTosUri,
                        tokenEndpointAuthMethod = newTokenEndpointAuthMethod,
                        scope = newScopes,
                        grantTypes = newGrantTypes,
                        responseTypes = newResponseTypes,
                        policyUri = newPolicyUri,
                        jwksUri = newJwksUri,
                        jwks = newJwks,
                        applicationType = newApplicationType,
                        sectorIdentifierUri = newSectorIdentifierUri,
                        subjectType = newSubjectType,
                        requestObjectSigningAlg = newRequestObjectSigningAlg,
                        userInfoSignedResponseAlg = newUserInfoSignedResponseAlg,
                        userInfoEncryptedResponseAlg = newUserInfoEncryptedResponseAlg,
                        userInfoEncryptedResponseEnc = newUserInfoEncryptedResponseEnc,
                        idTokenSignedResponseAlg = newIdTokenSignedResponseAlg,
                        idTokenEncryptedResponseAlg = newIdTokenEncryptedResponseAlg,
                        idTokenEncryptedResponseEnc = newIdTokenEncryptedResponseEnc,
                        tokenEndpointAuthSigningAlg = newTokenEndpointAuthSigningAlg,
                        defaultMaxAge = newDefaultMaxAge,
                        requireAuthTime = newRequireAuthTime,
                        defaultACRvalues = newDefaultACRvalues,
                        initiateLoginUri = newInitiateLoginUri,
                        postLogoutRedirectUris = newPostLogoutRedirectUris,
                        requestUris = newRequestUris,
                        claimsRedirectUris = newClaimsRedirectUris,
                    )

                    return updatedClient
                } catch (e: ParseException) {
                    throw ValidationException("invalid_client_metadata", "Software statement claims didn't parse", HttpStatus.BAD_REQUEST)
                }
            } else {
                throw ValidationException("invalid_client_metadata", "Software statement rejected by validator", HttpStatus.BAD_REQUEST)
            }
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/clients"

        /**
         * Logger for this class
         */
        private val logger = getLogger<ClientAPI>()
    }
}
