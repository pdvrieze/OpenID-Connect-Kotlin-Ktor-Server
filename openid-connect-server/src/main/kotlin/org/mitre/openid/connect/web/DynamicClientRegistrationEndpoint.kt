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
import org.mitre.jwt.assertion.AssertionValidator
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
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
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.exception.ValidationException
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.view.ClientInformationResponseView
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.oauth2.common.util.OAuth2Utils
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.util.UriUtils
import java.text.ParseException
import java.util.*
import java.util.concurrent.TimeUnit

@Controller
@RequestMapping(value = [DynamicClientRegistrationEndpoint.URL])
class DynamicClientRegistrationEndpoint {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Autowired
    private lateinit var blacklistService: BlacklistedSiteService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var connectTokenService: OIDCTokenService

    @Autowired
    @Qualifier("clientAssertionValidator")
    private lateinit var assertionValidator: AssertionValidator

    /**
     * Create a new Client, issue a client ID, and create a registration access token.
     */
    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun registerNewClient(@RequestBody jsonString: String?, m: Model): String {
        val newClientBuilder: ClientDetailsEntity.Builder?
        try {
            newClientBuilder = jsonString?.let { parse(it).builder() }
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("registerNewClient failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400
            return HttpCodeView.VIEWNAME
        }

        if (newClientBuilder == null) {
            // didn't parse, this is a bad request
            logger.error("registerNewClient failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400

            return HttpCodeView.VIEWNAME
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
            validateSoftwareStatement(newClientBuilder) // need to handle the software statement first because it might override requested values
            validateScopes(newClientBuilder)
            validateResponseTypes(newClientBuilder)
            validateGrantTypes(newClientBuilder)
            validateRedirectUris(newClientBuilder)
            validateAuth(newClientBuilder)
        } catch (ve: ValidationException) {
            // validation failed, return an error
            m.addAttribute(JsonErrorView.ERROR, ve.error)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, ve.errorDescription)
            m.addAttribute(HttpCodeView.CODE, ve.status)
            return JsonErrorView.VIEWNAME
        }

        if (newClientBuilder!!.tokenEndpointAuthMethod == null) {
            newClientBuilder.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        if (newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC || newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_JWT || newClientBuilder.tokenEndpointAuthMethod == AuthMethod.SECRET_POST) {
            // we need to generate a secret

            newClientBuilder.clientSecret = clientService.generateClientSecret(newClientBuilder)
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
            val savedClient = clientService.saveNewClient(newClientBuilder.build())

            // generate the registration access token
            var token = connectTokenService.createRegistrationAccessToken(savedClient)!!
            token = tokenService.saveAccessToken(token)

            // send it all out to the view
            val registered =
                RegisteredClient(savedClient, token.value, config.issuer + "register/" + UriUtils.encodePathSegment(savedClient.clientId, "UTF-8"))
            m.addAttribute("client", registered)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.CREATED) // http 201

            return ClientInformationResponseView.VIEWNAME
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)

            m.addAttribute(JsonErrorView.ERROR, "invalid_client_metadata")
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unable to save client due to invalid or inconsistent metadata.")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400

            return JsonErrorView.VIEWNAME
        }
    }

    /**
     * Get the meta information for a client.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun readClientConfiguration(@PathVariable("id") clientId: String, m: Model, auth: OAuth2Authentication): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null && client.clientId == auth.oAuth2Request.clientId) {
            val token = rotateRegistrationTokenIfNecessary(auth, client)
            val registered =
                RegisteredClient(client, token.value, config.issuer + "register/" + UriUtils.encodePathSegment(client.clientId, "UTF-8"))

            // send it all out to the view
            m.addAttribute("client", registered)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.OK) // http 200

            return ClientInformationResponseView.VIEWNAME
        } else {
            // client mismatch
            logger.error(
                "readClientConfiguration failed, client ID mismatch: "
                        + clientId + " and " + auth.oAuth2Request.clientId + " do not match."
            )
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN) // http 403

            return HttpCodeView.VIEWNAME
        }
    }

    /**
     * Update the metainformation for a given client.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun updateClient(
        @PathVariable("id") clientId: String,
        @RequestBody jsonString: String?,
        m: Model,
        auth: OAuth2Authentication
    ): String {
        val newClient: ClientDetailsEntity.Builder?
        try {
            newClient = jsonString?.let { parse(it).builder() }
        } catch (e: SerializationException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("updateClient failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400
            return HttpCodeView.VIEWNAME
        }

        val oldClient = clientService.loadClientByClientId(clientId)

        if (newClient == null || oldClient == null || oldClient.clientId != auth.oAuth2Request.clientId || oldClient.clientId != newClient.clientId
        ) {
            // client mismatch
            logger.error(
                "updateClient failed, client ID mismatch: $clientId and ${auth.oAuth2Request.clientId} do not match."
            )
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN) // http 403

            return HttpCodeView.VIEWNAME
        }

        // we have an existing client and the new one parsed

        // a client can't ask to update its own client secret to any particular value

        // we need to copy over all of the local and SECOAUTH fields
        newClient.clientSecret = oldClient.clientSecret
        newClient.accessTokenValiditySeconds = oldClient.accessTokenValiditySeconds
        newClient.idTokenValiditySeconds = oldClient.idTokenValiditySeconds
        newClient.refreshTokenValiditySeconds = oldClient.refreshTokenValiditySeconds
        newClient.isDynamicallyRegistered = true  // it's still dynamically registered
        newClient.isAllowIntrospection = false  // dynamically registered clients can't do introspection -- use the resource registration instead
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
            m.addAttribute(JsonErrorView.ERROR, ve.error)
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, ve.errorDescription)
            m.addAttribute(HttpCodeView.CODE, ve.status)
            return JsonErrorView.VIEWNAME
        }

        try {
            // save the client
            val savedClient = clientService.updateClient(oldClient, newClient.build())

            val token = rotateRegistrationTokenIfNecessary(auth, savedClient)

            val registered =
                RegisteredClient(savedClient, token.value, config.issuer + "register/" + UriUtils.encodePathSegment(savedClient.clientId, "UTF-8"))

            // send it all out to the view
            m.addAttribute("client", registered)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.OK) // http 200

            return ClientInformationResponseView.VIEWNAME
        } catch (e: IllegalArgumentException) {
            logger.error("Couldn't save client", e)

            m.addAttribute(JsonErrorView.ERROR, "invalid_client_metadata")
            m.addAttribute(JsonErrorView.ERROR_MESSAGE, "Unable to save client due to invalid or inconsistent metadata.")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400

            return JsonErrorView.VIEWNAME
        }
    }

    /**
     * Delete the indicated client from the system.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.REGISTRATION_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun deleteClient(@PathVariable("id") clientId: String, m: Model, auth: OAuth2Authentication): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null && client.clientId == auth.oAuth2Request.clientId) {
            clientService.deleteClient(client)

            m.addAttribute(HttpCodeView.CODE, HttpStatus.NO_CONTENT) // http 204

            return HttpCodeView.VIEWNAME
        } else {
            // client mismatch
            logger.error(
                "readClientConfiguration failed, client ID mismatch: "
                        + clientId + " and " + auth.oAuth2Request.clientId + " do not match."
            )
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN) // http 403

            return HttpCodeView.VIEWNAME
        }
    }

    @Throws(ValidationException::class)
    private fun validateScopes(newClient: ClientDetailsEntity.Builder) {
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
    private fun validateResponseTypes(newClient: ClientDetailsEntity.Builder) {
        // does not do anything
    }

    @Throws(ValidationException::class)
    private fun validateGrantTypes(builder: ClientDetailsEntity.Builder) {
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
            throw ValidationException("invalid_client_metadata", "The password grant type is not allowed in dynamic registration on this server.", HttpStatus.BAD_REQUEST)
        }

        // don't allow clients to have multiple incompatible grant types and scopes
        if (builder.authorizedGrantTypes.contains("authorization_code")) {
            // check for incompatible grants

            if (builder.authorizedGrantTypes.contains("implicit") ||
                (!config.isDualClient && builder.authorizedGrantTypes.contains("client_credentials"))
            ) {
                // return an error, you can't have these grant types together
                throw ValidationException("invalid_client_metadata", "Incompatible grant types requested: " + builder.authorizedGrantTypes, HttpStatus.BAD_REQUEST)
            }

            if (builder.responseTypes.contains("token")) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException("invalid_client_metadata", "Incompatible response types requested: " + builder.authorizedGrantTypes + " / " + builder.responseTypes, HttpStatus.BAD_REQUEST)
            }

            builder.responseTypes.add("code")
        }

        if (builder.authorizedGrantTypes.contains("implicit")) {
            // check for incompatible grants

            if (builder.authorizedGrantTypes.contains("authorization_code") ||
                (!config.isDualClient && builder.authorizedGrantTypes.contains("client_credentials"))
            ) {
                // return an error, you can't have these grant types together
                throw ValidationException("invalid_client_metadata", "Incompatible grant types requested: " + builder.authorizedGrantTypes, HttpStatus.BAD_REQUEST)
            }

            if (builder.responseTypes.contains("code")) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException("invalid_client_metadata", "Incompatible response types requested: " + builder.authorizedGrantTypes + " / " + builder.responseTypes, HttpStatus.BAD_REQUEST)
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
                throw ValidationException("invalid_client_metadata", "Incompatible grant types requested: " + builder.authorizedGrantTypes, HttpStatus.BAD_REQUEST)
            }

            if (!builder.responseTypes.isEmpty()) {
                // return an error, you can't have this grant type and response type together
                throw ValidationException("invalid_client_metadata", "Incompatible response types requested: " + builder.authorizedGrantTypes + " / " + builder.responseTypes, HttpStatus.BAD_REQUEST)
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
            throw ValidationException("invalid_client_metadata", "Clients must register at least one grant type.", HttpStatus.BAD_REQUEST)
        }

    }

    @Throws(ValidationException::class)
    private fun validateRedirectUris(newClient: ClientDetailsEntity.Builder) {
        // check to make sure this client registered a redirect URI if using a redirect flow
        if (newClient.authorizedGrantTypes.contains("authorization_code") || newClient.authorizedGrantTypes.contains("implicit")) {
            if (newClient.redirectUris.isEmpty()) {
                // return an error
                throw ValidationException("invalid_redirect_uri", "Clients using a redirect-based grant type must register at least one redirect URI.", HttpStatus.BAD_REQUEST)
            }

            for (uri in newClient.redirectUris) {
                if (blacklistService.isBlacklisted(uri)) {
                    // return an error
                    throw ValidationException("invalid_redirect_uri", "Redirect URI is not allowed: $uri", HttpStatus.BAD_REQUEST)
                }

                if (uri.contains("#")) {
                    // if it contains the hash symbol then it has a fragment, which isn't allowed
                    throw ValidationException("invalid_redirect_uri", "Redirect URI can not have a fragment", HttpStatus.BAD_REQUEST)
                }
            }
        }
    }

    @Throws(ValidationException::class)
    private fun validateAuth(newClient: ClientDetailsEntity.Builder) {
        if (newClient.tokenEndpointAuthMethod == null) {
            newClient.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        when (newClient.tokenEndpointAuthMethod) {
            AuthMethod.SECRET_BASIC,
            AuthMethod.SECRET_JWT,
            AuthMethod.SECRET_POST -> {
                if (newClient.clientSecret.isNullOrEmpty()) {
                    // no secret yet, we need to generate a secret
                    newClient.clientSecret = clientService.generateClientSecret(newClient)
                }
            }

            AuthMethod.PRIVATE_KEY -> {
                if (newClient.jwksUri.isNullOrEmpty() && newClient.jwks == null) {
                    throw ValidationException("invalid_client_metadata", "JWK Set URI required when using private key authentication", HttpStatus.BAD_REQUEST)
                }

                newClient.clientSecret = null
            }

            AuthMethod.NONE -> newClient.clientSecret = null

            else -> throw ValidationException("invalid_client_metadata", "Unknown authentication method", HttpStatus.BAD_REQUEST)
        }
    }


    /**
     * @throws ValidationException
     */
    @Throws(ValidationException::class)
    private fun validateSoftwareStatement(newClient: ClientDetailsEntity.Builder) {
        if (newClient.softwareStatement == null) return

        if (!assertionValidator.isValid(newClient.softwareStatement!!)) {
            throw ValidationException("invalid_client_metadata", "Software statement rejected by validator", HttpStatus.BAD_REQUEST)
        }

        try {
            val claimSet = newClient.softwareStatement!!.jwtClaimsSet
            for (claim in claimSet.claims.keys) {
                when (claim) {
                    SOFTWARE_STATEMENT -> throw ValidationException("invalid_client_metadata", "Software statement can't include another software statement", HttpStatus.BAD_REQUEST)
                    CLAIMS_REDIRECT_URIS -> newClient.claimsRedirectUris =
                        claimSet.getStringListClaim(claim).toHashSet()

                    CLIENT_SECRET_EXPIRES_AT -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client secret expiration time", HttpStatus.BAD_REQUEST)
                    CLIENT_ID_ISSUED_AT -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client ID issuance time", HttpStatus.BAD_REQUEST)
                    REGISTRATION_CLIENT_URI -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client configuration endpoint", HttpStatus.BAD_REQUEST)
                    REGISTRATION_ACCESS_TOKEN -> throw ValidationException("invalid_client_metadata", "Software statement can't include a client registration access token", HttpStatus.BAD_REQUEST)
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
                        newClient.scope =
                            OAuth2Utils.parseParameterList(claimSet.getStringClaim(claim))?.toHashSet()
                                ?: hashSetOf()
                    }

                    TOKEN_ENDPOINT_AUTH_METHOD -> newClient.tokenEndpointAuthMethod =
                        OAuthClientDetails.AuthMethod.getByValue(claimSet.getStringClaim(claim))

                    TOS_URI -> newClient.tosUri = claimSet.getStringClaim(claim)
                    CONTACTS -> newClient.contacts = claimSet.getStringListClaim(claim).toHashSet()
                    LOGO_URI -> newClient.logoUri = claimSet.getStringClaim(claim)
                    CLIENT_URI -> newClient.clientUri = claimSet.getStringClaim(claim)
                    CLIENT_NAME -> newClient.clientName = claimSet.getStringClaim(claim)
                    REDIRECT_URIS -> newClient.redirectUris =
                        claimSet.getStringListClaim(claim).toHashSet()

                    CLIENT_SECRET -> throw ValidationException("invalid_client_metadata", "Software statement can't contain client secret", HttpStatus.BAD_REQUEST)
                    CLIENT_ID -> throw ValidationException("invalid_client_metadata", "Software statement can't contain client ID", HttpStatus.BAD_REQUEST)

                    else -> logger.warn("Software statement contained unknown field: " + claim + " with value " + claimSet.getClaim(claim))
                }
            }
        } catch (e: ParseException) {
            throw ValidationException("invalid_client_metadata", "Software statement claims didn't parse", HttpStatus.BAD_REQUEST)
        }
    }


    /*
	 * Rotates the registration token if it's expired, otherwise returns it
	 */
    private fun rotateRegistrationTokenIfNecessary(
        auth: OAuth2Authentication,
        client: OAuthClientDetails
    ): OAuth2AccessTokenEntity {
        val details = auth.details as OAuth2AuthenticationDetails
        val token = tokenService.readAccessToken(details.tokenValue)

        if (config.regTokenLifeTime != null) {
            try {
                // Re-issue the token if it has been issued before [currentTime - validity]
                val validToDate = Date(System.currentTimeMillis() - config.regTokenLifeTime!! * 1000)
                if (token.jwt!!.jwtClaimsSet.issueTime.before(validToDate)) {
                    logger.info("Rotating the registration access token for " + client.clientId)
                    tokenService.revokeAccessToken(token)
                    val newToken = connectTokenService.createRegistrationAccessToken(client)
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

    companion object {
        const val URL: String = "register"

        /**
         * Logger for this class
         */
        private val logger = getLogger<DynamicClientRegistrationEndpoint>()
    }
}
