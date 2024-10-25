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
import org.mitre.oauth2.exception.OAuthErrorCodes.*
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RequestAuthentication
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.OAuthClientDetails.AuthMethod
import org.mitre.oauth2.model.RegisteredClient
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
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse
import org.mitre.openid.connect.exception.ValidationException
import org.mitre.openid.connect.view.clientInformationResponseView
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.assertionValidator
import org.mitre.web.util.blacklistedSiteService
import org.mitre.web.util.clientDetailsService
import org.mitre.web.util.oidcTokenService
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import org.mitre.web.util.scopeService
import org.mitre.web.util.tokenService
import java.text.ParseException
import java.util.*
import java.util.concurrent.TimeUnit

//@Controller
//@RequestMapping(value = ["register"])
object DynamicClientRegistrationEndpoint: KtorEndpoint {

    override fun Route.addRoutes() {
        route("/register") {
            post { registerNewClient() }
            authenticate {
                get("/{id}") { readClientConfiguration() }
                put("/{id}") { updateClient() }
                delete("/{id}") { deleteClient() }
            }
        }
    }

    /**
     * Create a new Client, issue a client ID, and create a registration access token.
     */
//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.registerNewClient() {
        val config = openIdContext.config

        val newClientBuilder: ClientDetailsEntity.Builder?
        try {
            newClientBuilder = parse(call.receiveText()).builder()
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("registerNewClient failed; submitted JSON is malformed")
            return call.respond(HttpStatusCode.BadRequest)
        }

        //
        // Now do some post-processing consistency checks on it
        //

        // clear out any spurious id/secret (clients don't get to pick)

        newClientBuilder.clientId = null
        newClientBuilder.clientSecret = null

        // do validation on the fields
        try {
            validateSoftwareStatement(newClientBuilder) // need to handle the software statement first because it might override requested values
            validateScopes(newClientBuilder)
            validateResponseTypes(newClientBuilder)
            validateGrantTypes(newClientBuilder)
            validateRedirectUris(newClientBuilder)
            validateAuth(newClientBuilder)
        } catch (ve: ValidationException) {
            return jsonErrorView(ve)
        }

        if (newClientBuilder.tokenEndpointAuthMethod == null) {
            newClientBuilder.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        if (newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC || newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_JWT || newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_POST) {
            // we need to generate a secret

            newClientBuilder.clientSecret = clientDetailsService.generateClientSecret(newClientBuilder)
        }

        // set some defaults for token timeouts
        if (config.isHeartMode) {
            // heart mode has different defaults depending on primary grant type
            if (newClientBuilder.authorizedGrantTypes.contains("authorization_code")) {
                newClientBuilder.accessTokenValiditySeconds = TimeUnit.HOURS.toSeconds(1).toInt()
                // access tokens good for 1hr
                newClientBuilder.idTokenValiditySeconds =
                    TimeUnit.MINUTES.toSeconds(5).toInt() // id tokens good for 5min
                newClientBuilder.refreshTokenValiditySeconds = TimeUnit.HOURS.toSeconds(24).toInt()
                // refresh tokens good for 24hr
            } else if (newClientBuilder.authorizedGrantTypes.contains("implicit")) {
                newClientBuilder.accessTokenValiditySeconds = TimeUnit.MINUTES.toSeconds(15).toInt()
                // access tokens good for 15min
                newClientBuilder.idTokenValiditySeconds =
                    TimeUnit.MINUTES.toSeconds(5).toInt() // id tokens good for 5min
                newClientBuilder.refreshTokenValiditySeconds = 0
                // no refresh tokens
            } else if (newClientBuilder.authorizedGrantTypes.contains("client_credentials")) {
                newClientBuilder.accessTokenValiditySeconds = TimeUnit.HOURS.toSeconds(6).toInt()
                // access tokens good for 6hr
                newClientBuilder.idTokenValiditySeconds = 0 // no id tokens
                newClientBuilder.refreshTokenValiditySeconds = 0
                // no refresh tokens
            }
        } else {
            newClientBuilder.accessTokenValiditySeconds = TimeUnit.HOURS.toSeconds(1).toInt()
            // access tokens good for 1hr
            newClientBuilder.idTokenValiditySeconds = TimeUnit.MINUTES.toSeconds(10).toInt() // id tokens good for 10min
            newClientBuilder.refreshTokenValiditySeconds = null // refresh tokens good until revoked
        }

        // this client has been dynamically registered (obviously)
        newClientBuilder.isDynamicallyRegistered = true

        // this client can't do token introspection
        newClientBuilder.isAllowIntrospection = false

        // now save it
        try {
            val savedClient = clientDetailsService.saveNewClient(newClientBuilder.build())

            // generate the registration access token
            var token = oidcTokenService.createRegistrationAccessToken(savedClient)!!
            token = tokenService.saveAccessToken(token)

            // send it all out to the view
            val registered = RegisteredClient(savedClient, token.value, clientRegistrationUri(savedClient))
            return clientInformationResponseView(registered, HttpStatusCode.Created)
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)

            return jsonErrorView(INVALID_CLIENT_METADATA, "Unable to save client due to invalid or inconsistent metadata.")
        }
    }

    /**
     * Get the meta information for a client.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.readClientConfiguration() {
        val auth = requireRole(GrantedAuthority.ROLE_CLIENT, SystemScopeService.REGISTRATION_TOKEN_SCOPE) { return }
        val clientId = call.parameters["id"]!!

        val client = clientDetailsService.loadClientByClientId(clientId)

        if (client != null && client.clientId == auth.authorizationRequest.clientId) {
            val token = rotateRegistrationTokenIfNecessary(auth, client)
            val registered = RegisteredClient(client, token.value, clientRegistrationUri(client))

            return clientInformationResponseView(registered, HttpStatusCode.OK)
        } else {
            // client mismatch
            logger.error("readClientConfiguration failed, client ID mismatch: $clientId and ${auth.authorizationRequest.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }
    }

    /**
     * Update the metainformation for a given client.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.updateClient() {
        val auth = requireRole(GrantedAuthority.ROLE_CLIENT, SystemScopeService.REGISTRATION_TOKEN_SCOPE) { return }
        val clientId = call.parameters["id"]!!

        val newClient: ClientDetailsEntity.Builder?
        try {
            newClient = parse(call.receiveText()).builder()
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("updateClient failed; submitted JSON is malformed")
            return call.respond(HttpStatusCode.BadRequest)
        }

        val oldClient = clientDetailsService.loadClientByClientId(clientId)

        if (newClient == null || oldClient == null || oldClient.clientId != auth.authorizationRequest.clientId || oldClient.clientId != newClient.clientId
        ) {
            // client mismatch
            logger.error("updateClient failed, client ID mismatch: $clientId and ${auth.authorizationRequest.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }

        // we have an existing client and the new one parsed

        // a client can't ask to update its own client secret to any particular value

        // we need to copy over all of the local and SECOAUTH fields
        newClient.clientSecret = oldClient.clientSecret
        newClient.accessTokenValiditySeconds = oldClient.accessTokenValiditySeconds
        newClient.idTokenValiditySeconds = oldClient.idTokenValiditySeconds
        newClient.refreshTokenValiditySeconds = oldClient.refreshTokenValiditySeconds
        newClient.isDynamicallyRegistered = true  // it's still dynamically registered
        newClient.isAllowIntrospection =
            false  // dynamically registered clients can't do introspection -- use the resource registration instead
        newClient.authorities = oldClient.authorities.toHashSet()
        newClient.clientDescription = oldClient.clientDescription
        newClient.createdAt = oldClient.createdAt
        newClient.isReuseRefreshToken = oldClient.isReuseRefreshToken

        // do validation on the fields
        try {
            validateSoftwareStatement(newClient) // need to handle the software statement first because it might override requested values
            validateScopes(newClient)
            validateResponseTypes(newClient)
            validateGrantTypes(newClient)
            validateRedirectUris(newClient)
            validateAuth(newClient)
        } catch (ve: ValidationException) {
            // validation failed, return an error
            return jsonErrorView(ve)
        }

        try {
            // save the client
            val savedClient = clientDetailsService.updateClient(oldClient, newClient.build())

            val token = rotateRegistrationTokenIfNecessary(auth, savedClient)

            val registered = RegisteredClient(savedClient, token.value, clientRegistrationUri(savedClient))
            return clientInformationResponseView(registered)
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)
            return jsonErrorView(
                INVALID_CLIENT_METADATA,
                "Unable to save client due to invalid or inconsistent metadata."
            )
        }
    }

    /**
     * Delete the indicated client from the system.
     */
//    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
//    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.deleteClient() {
        val auth = requireRole(GrantedAuthority.ROLE_CLIENT, SystemScopeService.REGISTRATION_TOKEN_SCOPE) { return }
        val clientId = call.parameters["id"]!!
        val client = clientDetailsService.loadClientByClientId(clientId)

        if (client != null && client.clientId == auth.authorizationRequest.clientId) {
            clientDetailsService.deleteClient(client)
            return call.respond(HttpStatusCode.NoContent)
        } else {
            // client mismatch
            logger.error("readClientConfiguration failed, client ID mismatch: $clientId and ${auth.authorizationRequest.clientId} do not match.")
            return call.respond(HttpStatusCode.Forbidden)
        }
    }

    @Throws(ValidationException::class)
    private fun RoutingContext.validateScopes(newClient: ClientDetailsEntity.Builder) {
        // scopes that the client is asking for
        val requestedScopes = scopeService.fromStrings(newClient.scope)

        // the scopes that the client can have must be a subset of the dynamically allowed scopes
        var allowedScopes: Set<SystemScope>? = scopeService.removeRestrictedAndReservedScopes(requestedScopes)

        // if the client didn't ask for any, give them the defaults
        if (allowedScopes.isNullOrEmpty()) {
            allowedScopes = scopeService.defaults
        }

        newClient.scope = scopeService.toStrings(allowedScopes)?.toHashSet()
    }

    @Throws(ValidationException::class)
    private fun RoutingContext.validateResponseTypes(newClient: ClientDetailsEntity.Builder) {
        // does not do anything
    }

    @Throws(ValidationException::class)
    private fun RoutingContext.validateGrantTypes(builder: ClientDetailsEntity.Builder) {
        val config = openIdContext.config
        if (builder.authorizedGrantTypes.isEmpty()) {
            if (builder.scope?.contains("offline_access") == true) { // client asked for offline access
                builder.authorizedGrantTypes =
                    hashSetOf("authorization_code", "refresh_token") // allow authorization code and refresh token grant types by default
            } else {
                builder.authorizedGrantTypes =
                    hashSetOf("authorization_code") // allow authorization code grant type by default
            }
            if (config.isDualClient) {
                val extendedGrandTypes = builder.authorizedGrantTypes
                extendedGrandTypes.add("client_credentials")
                builder.authorizedGrantTypes = extendedGrandTypes
            }
        }

        // set default grant types if needed

        // filter out unknown grant types
        // TODO: make this a pluggable service
        val requestedGrantTypes: MutableSet<String> = HashSet(builder.authorizedGrantTypes)
        requestedGrantTypes.retainAll(
            setOf("authorization_code", "implicit", "password", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant_type:redelegate")
        )

        // don't allow "password" grant type for dynamic registration
        if (builder.authorizedGrantTypes.contains("password")) {
            // return an error, you can't dynamically register for the password grant
            throw ValidationException(INVALID_CLIENT_METADATA, "The password grant type is not allowed in dynamic registration on this server.")
        }

        // don't allow clients to have multiple incompatible grant types and scopes
        if (builder.authorizedGrantTypes.contains("authorization_code")) {
            // check for incompatible grants

            if (builder.authorizedGrantTypes.contains("implicit") ||
                (!config.isDualClient && builder.authorizedGrantTypes.contains("client_credentials"))
            ) {
                // return an error, you can't have these grant types together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible grant types requested: ${builder.authorizedGrantTypes}")
            }

            if (builder.responseTypes.contains("token")) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible response types requested: ${builder.authorizedGrantTypes} / ${builder.responseTypes}", )
            }

            builder.responseTypes.add("code")
        }

        if (builder.authorizedGrantTypes.contains("implicit")) {
            // check for incompatible grants

            if (builder.authorizedGrantTypes.contains("authorization_code") ||
                (!config.isDualClient && builder.authorizedGrantTypes.contains("client_credentials"))
            ) {
                // return an error, you can't have these grant types together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible grant types requested: " + builder.authorizedGrantTypes)
            }

            if (builder.responseTypes.contains("code")) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible response types requested: " + builder.authorizedGrantTypes + " / " + builder.responseTypes)
            }

            builder.responseTypes.add("token")

            // don't allow refresh tokens in implicit clients
            builder.authorizedGrantTypes.remove("refresh_token")
            builder.scope?.remove(SystemScopeService.OFFLINE_ACCESS)
        }

        if (builder.authorizedGrantTypes.contains("client_credentials")) {
            // check for incompatible grants

            if (!config.isDualClient &&
                (builder.authorizedGrantTypes.contains("authorization_code") || builder.authorizedGrantTypes.contains("implicit"))
            ) {
                // return an error, you can't have these grant types together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible grant types requested: " + builder.authorizedGrantTypes)
            }

            if (!builder.responseTypes.isEmpty()) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException(INVALID_CLIENT_METADATA, "Incompatible response types requested: " + builder.authorizedGrantTypes + " / " + builder.responseTypes)
            }

            // don't allow refresh tokens or id tokens in client_credentials clients
            builder.authorizedGrantTypes.remove("refresh_token")
            builder.scope?.run {
                remove(SystemScopeService.OFFLINE_ACCESS)
                remove(SystemScopeService.OPENID_SCOPE)
            }
        }

        if (builder.authorizedGrantTypes.isEmpty()) {
            // return an error, you need at least one grant type selected
            throw ValidationException(INVALID_CLIENT_METADATA, "Clients must register at least one grant type.")
        }

    }

    @Throws(ValidationException::class)
    private fun RoutingContext.validateRedirectUris(newClient: ClientDetailsEntity.Builder) {
        // check to make sure this client registered a redirect URI if using a redirect flow
        if (newClient.authorizedGrantTypes.contains("authorization_code") || newClient.authorizedGrantTypes.contains("implicit")) {
            if (newClient.redirectUris.isEmpty()) {
                // return an error
                throw ValidationException(INVALID_REDIRECT_URI, "Clients using a redirect-based grant type must register at least one redirect URI.")
            }

            for (uri in newClient.redirectUris) {
                if (blacklistedSiteService.isBlacklisted(uri)) {
                    // return an error
                    throw ValidationException(INVALID_REDIRECT_URI, "Redirect URI is not allowed: $uri")
                }

                if (uri.contains("#")) {
                    // if it contains the hash symbol then it has a fragment, which isn't allowed
                    throw ValidationException(INVALID_REDIRECT_URI, "Redirect URI can not have a fragment")
                }
            }
        }
    }

    @Throws(ValidationException::class)
    private fun RoutingContext.validateAuth(newClient: ClientDetailsEntity.Builder) {
        if (newClient.tokenEndpointAuthMethod == null) {
            newClient.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        when (newClient.tokenEndpointAuthMethod) {
            AuthMethod.SECRET_BASIC,
            AuthMethod.SECRET_JWT,
            AuthMethod.SECRET_POST -> {
                if (newClient.clientSecret.isNullOrEmpty()) {
                    // no secret yet, we need to generate a secret
                    newClient.clientSecret = clientDetailsService.generateClientSecret(newClient)
                }
            }

            AuthMethod.PRIVATE_KEY -> {
                if (newClient.jwksUri.isNullOrEmpty() && newClient.jwks == null) {
                    throw ValidationException(INVALID_CLIENT_METADATA, "JWK Set URI required when using private key authentication")
                }

                newClient.clientSecret = null
            }

            AuthMethod.NONE -> newClient.clientSecret = null

            else -> throw ValidationException(INVALID_CLIENT_METADATA, "Unknown authentication method")
        }
    }


    /**
     * @throws ValidationException
     */
    @Throws(ValidationException::class)
    private suspend fun RoutingContext.validateSoftwareStatement(newClient: ClientDetailsEntity.Builder) {
        if (newClient.softwareStatement == null) return

        if (!assertionValidator.isValid(newClient.softwareStatement!!)) {
            throw ValidationException(INVALID_CLIENT_METADATA, "Software statement rejected by validator")
        }

        try {
            val claimSet = newClient.softwareStatement!!.jwtClaimsSet
            for (claim in claimSet.claims.keys) {
                when (claim) {
                    SOFTWARE_STATEMENT -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't include another software statement")
                    CLAIMS_REDIRECT_URIS -> newClient.claimsRedirectUris =
                        claimSet.getStringListClaim(claim).toHashSet()

                    CLIENT_SECRET_EXPIRES_AT -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't include a client secret expiration time")
                    CLIENT_ID_ISSUED_AT -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't include a client ID issuance time")
                    REGISTRATION_CLIENT_URI -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't include a client configuration endpoint")
                    REGISTRATION_ACCESS_TOKEN -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't include a client registration access token")
                    REQUEST_URIS -> newClient.requestUris = claimSet.getStringListClaim(claim).toHashSet()
                    POST_LOGOUT_REDIRECT_URIS -> newClient.postLogoutRedirectUris =
                        claimSet.getStringListClaim(claim).toHashSet()

                    INITIATE_LOGIN_URI -> newClient.initiateLoginUri = claimSet.getStringClaim(claim)
                    DEFAULT_ACR_VALUES -> newClient.defaultACRvalues =
                        claimSet.getStringListClaim(claim).toHashSet()

                    REQUIRE_AUTH_TIME -> newClient.requireAuthTime = claimSet.getBooleanClaim(claim)
                    DEFAULT_MAX_AGE -> newClient.defaultMaxAge = claimSet.getIntegerClaim(claim)?.toLong()
                    TOKEN_ENDPOINT_AUTH_SIGNING_ALG -> newClient.tokenEndpointAuthSigningAlg =
                        JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                    ID_TOKEN_ENCRYPTED_RESPONSE_ENC -> newClient.idTokenEncryptedResponseEnc =
                        EncryptionMethod.parse(claimSet.getStringClaim(claim))

                    ID_TOKEN_ENCRYPTED_RESPONSE_ALG -> newClient.idTokenEncryptedResponseAlg =
                        JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                    ID_TOKEN_SIGNED_RESPONSE_ALG -> newClient.idTokenSignedResponseAlg =
                        JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                    USERINFO_ENCRYPTED_RESPONSE_ENC -> newClient.userInfoEncryptedResponseEnc =
                        EncryptionMethod.parse(claimSet.getStringClaim(claim))

                    USERINFO_ENCRYPTED_RESPONSE_ALG -> newClient.userInfoEncryptedResponseAlg =
                        JWEAlgorithm.parse(claimSet.getStringClaim(claim))

                    USERINFO_SIGNED_RESPONSE_ALG -> newClient.userInfoSignedResponseAlg =
                        JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                    REQUEST_OBJECT_SIGNING_ALG -> newClient.requestObjectSigningAlg =
                        JWSAlgorithm.parse(claimSet.getStringClaim(claim))

                    SUBJECT_TYPE -> newClient.subjectType =
                        OAuthClientDetails.SubjectType.getByValue(claimSet.getStringClaim(claim))

                    SECTOR_IDENTIFIER_URI -> newClient.sectorIdentifierUri = claimSet.getStringClaim(claim)
                    APPLICATION_TYPE -> newClient.applicationType =
                        OAuthClientDetails.AppType.valueOf(claimSet.getStringClaim(claim))

                    JWKS_URI -> newClient.jwksUri = claimSet.getStringClaim(claim)
                    JWKS -> newClient.jwks =
                        JWKSet.parse(JSONObjectUtils.toJSONString(claimSet.getJSONObjectClaim(claim)))

                    POLICY_URI -> newClient.policyUri = claimSet.getStringClaim(claim)
                    RESPONSE_TYPES -> newClient.responseTypes =
                        claimSet.getStringListClaim(claim).toHashSet()

                    GRANT_TYPES -> newClient.authorizedGrantTypes =
                        claimSet.getStringListClaim(claim).toHashSet()

                    SCOPE -> {
                        newClient.scope = claimSet.getStringClaim(claim).splitToSequence(' ')
                            .filterNotTo(HashSet()) { it.isBlank() }
                    }

                    TOKEN_ENDPOINT_AUTH_METHOD -> newClient.tokenEndpointAuthMethod =
                        AuthMethod.getByValue(claimSet.getStringClaim(claim))

                    TOS_URI -> newClient.tosUri = claimSet.getStringClaim(claim)
                    CONTACTS -> newClient.contacts = claimSet.getStringListClaim(claim).toHashSet()
                    LOGO_URI -> newClient.logoUri = claimSet.getStringClaim(claim)
                    CLIENT_URI -> newClient.clientUri = claimSet.getStringClaim(claim)
                    CLIENT_NAME -> newClient.clientName = claimSet.getStringClaim(claim)
                    REDIRECT_URIS -> newClient.redirectUris =
                        claimSet.getStringListClaim(claim).toHashSet()

                    CLIENT_SECRET -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't contain client secret")
                    CLIENT_ID -> throw ValidationException(INVALID_CLIENT_METADATA, "Software statement can't contain client ID")

                    else -> logger.warn("Software statement contained unknown field: " + claim + " with value " + claimSet.getClaim(claim))
                }
            }
        } catch (e: ParseException) {
            throw ValidationException(INVALID_CLIENT_METADATA, "Software statement claims didn't parse")
        }
    }


    /*
	 * Rotates the registration token if it's expired, otherwise returns it
	 */
    private fun RoutingContext.rotateRegistrationTokenIfNecessary(
        auth: OAuth2RequestAuthentication,
        client: OAuthClientDetails
    ): OAuth2AccessTokenEntity {
        val details = auth.authorizationRequest
        val token = tokenService.readAccessToken(/*details.tokenValue*/TODO("Fix token handling"))
        val config = openIdContext.config

        if (config.regTokenLifeTime != null) {
            try {
                // Re-issue the token if it has been issued before [currentTime - validity]
                val validToDate = Date(System.currentTimeMillis() - config.regTokenLifeTime!! * 1000)
                if (token.jwt.jwtClaimsSet.issueTime.before(validToDate)) {
                    logger.info("Rotating the registration access token for " + client.clientId)
                    tokenService.revokeAccessToken(token)
                    val newToken = oidcTokenService.createRegistrationAccessToken(client)
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

    const val URL: String = "register"

    /**
     * Logger for this class
     */
    private val logger = getLogger<DynamicClientRegistrationEndpoint>()
}


