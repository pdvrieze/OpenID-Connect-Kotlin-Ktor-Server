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

import com.google.common.base.Strings
import com.google.gson.JsonSyntaxException
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.oauth2.service.OAuth2TokenEntityService
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parse
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.exception.ValidationException
import org.mitre.openid.connect.service.OIDCTokenService
import org.mitre.openid.connect.view.ClientInformationResponseView
import org.mitre.openid.connect.view.HttpCodeView
import org.mitre.openid.connect.view.JsonErrorView
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
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

@Controller
@RequestMapping(value = [ProtectedResourceRegistrationEndpoint.URL])
class ProtectedResourceRegistrationEndpoint {
    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var tokenService: OAuth2TokenEntityService

    @Autowired
    private lateinit var scopeService: SystemScopeService

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var connectTokenService: OIDCTokenService

    /**
     * Create a new Client, issue a client ID, and create a registration access token.
     */
    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun registerNewProtectedResource(@RequestBody jsonString: String?, m: Model): String {
        var newClient: ClientDetailsEntity? = null
        try {
            newClient = parse(jsonString)
        } catch (e: JsonSyntaxException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("registerNewProtectedResource failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400
            return HttpCodeView.VIEWNAME
        }

        if (newClient != null) {
            // it parsed!

            //
            // Now do some post-processing consistency checks on it
            //

            // clear out any spurious id/secret (clients don't get to pick)

            newClient.clientId = null
            newClient.clientSecret = null

            // do validation on the fields
            try {
                newClient = validateScopes(newClient)
                newClient = validateAuth(newClient)
            } catch (ve: ValidationException) {
                // validation failed, return an error
                m.addAttribute(JsonErrorView.ERROR, ve.error)
                m.addAttribute(JsonErrorView.ERROR_MESSAGE, ve.errorDescription)
                m.addAttribute(HttpCodeView.CODE, ve.status)
                return JsonErrorView.VIEWNAME
            }


            // no grant types are allowed
            newClient!!.grantTypes = HashSet()
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

            // now save it
            try {
                val savedClient = clientService.saveNewClient(newClient)

                // generate the registration access token
                val token = connectTokenService.createResourceAccessToken(savedClient!!)
                tokenService.saveAccessToken(token!!)

                // send it all out to the view
                val registered =
                    RegisteredClient(savedClient, token.value, config.issuer + "resource/" + UriUtils.encodePathSegment(savedClient.clientId!!, "UTF-8"))
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
        } else {
            // didn't parse, this is a bad request
            logger.error("registerNewClient failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400

            return HttpCodeView.VIEWNAME
        }
    }

    @Throws(ValidationException::class)
    private fun validateScopes(newClient: ClientDetailsEntity): ClientDetailsEntity {
        // scopes that the client is asking for
        val requestedScopes = scopeService.fromStrings(newClient.scope)!!

        // the scopes that the client can have must be a subset of the dynamically allowed scopes
        var allowedScopes: Set<SystemScope>? = scopeService.removeRestrictedAndReservedScopes(requestedScopes)

        // if the client didn't ask for any, give them the defaults
        if (allowedScopes.isNullOrEmpty()) {
            allowedScopes = scopeService.defaults
        }

        newClient.setScope(scopeService.toStrings(allowedScopes))

        return newClient
    }

    /**
     * Get the meta information for a client.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun readResourceConfiguration(@PathVariable("id") clientId: String, m: Model, auth: OAuth2Authentication): String {
        val client = clientService.loadClientByClientId(clientId)

        if (client != null && client.clientId == auth.oAuth2Request.clientId) {
            // possibly update the token

            val token = fetchValidRegistrationToken(auth, client)

            val registered =
                RegisteredClient(client, token!!.value, config.issuer + "resource/" + UriUtils.encodePathSegment(client.clientId, "UTF-8"))

            // send it all out to the view
            m.addAttribute("client", registered)
            m.addAttribute(HttpCodeView.CODE, HttpStatus.OK) // http 200

            return ClientInformationResponseView.VIEWNAME
        } else {
            // client mismatch
            logger.error(
                "readResourceConfiguration failed, client ID mismatch: "
                        + clientId + " and " + auth.oAuth2Request.clientId + " do not match."
            )
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN) // http 403

            return HttpCodeView.VIEWNAME
        }
    }

    /**
     * Update the metainformation for a given client.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.PUT], produces = [MediaType.APPLICATION_JSON_VALUE], consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun updateProtectedResource(
        @PathVariable("id") clientId: String,
        @RequestBody jsonString: String?,
        m: Model,
        auth: OAuth2Authentication
    ): String {
        var newClient: ClientDetailsEntity? = null
        try {
            newClient = parse(jsonString)
        } catch (e: JsonSyntaxException) {
            // bad parse
            // didn't parse, this is a bad request
            logger.error("updateProtectedResource failed; submitted JSON is malformed")
            m.addAttribute(HttpCodeView.CODE, HttpStatus.BAD_REQUEST) // http 400
            return HttpCodeView.VIEWNAME
        }

        val oldClient = clientService.loadClientByClientId(clientId)

        if (// we have an existing client and the new one parsed
            newClient != null && oldClient != null && oldClient.clientId == auth.oAuth2Request.clientId && oldClient.clientId == newClient.clientId // the client passed in the body matches the one in the URI
        ) {
            // a client can't ask to update its own client secret to any particular value

            newClient.clientSecret = oldClient.clientSecret

            newClient.createdAt = oldClient.createdAt

            // no grant types are allowed
            newClient.grantTypes = HashSet()
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
                newClient = validateScopes(newClient)
                newClient = validateAuth(newClient)
            } catch (ve: ValidationException) {
                // validation failed, return an error
                m.addAttribute(JsonErrorView.ERROR, ve.error)
                m.addAttribute(JsonErrorView.ERROR_MESSAGE, ve.errorDescription)
                m.addAttribute(HttpCodeView.CODE, ve.status)
                return JsonErrorView.VIEWNAME
            }


            try {
                // save the client
                val savedClient = clientService.updateClient(oldClient, newClient)

                // possibly update the token
                val token = fetchValidRegistrationToken(auth, savedClient)

                val registered =
                    RegisteredClient(savedClient, token!!.value, config.issuer + "resource/" + UriUtils.encodePathSegment(savedClient.clientId, "UTF-8"))

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
        } else {
            // client mismatch
            logger.error(
                "updateProtectedResource" +
                        " failed, client ID mismatch: "
                        + clientId + " and " + auth.oAuth2Request.clientId + " do not match."
            )
            m.addAttribute(HttpCodeView.CODE, HttpStatus.FORBIDDEN) // http 403

            return HttpCodeView.VIEWNAME
        }
    }

    /**
     * Delete the indicated client from the system.
     */
    @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('" + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
    @RequestMapping(value = ["/{id}"], method = [RequestMethod.DELETE], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun deleteResource(@PathVariable("id") clientId: String, m: Model, auth: OAuth2Authentication): String {
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
    private fun validateAuth(newClient: ClientDetailsEntity?): ClientDetailsEntity? {
        var newClient = newClient
        if (newClient!!.tokenEndpointAuthMethod == null) {
            newClient.tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC
        }

        if (newClient.tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC || newClient.tokenEndpointAuthMethod == AuthMethod.SECRET_JWT || newClient.tokenEndpointAuthMethod == AuthMethod.SECRET_POST) {
            if (Strings.isNullOrEmpty(newClient.clientSecret)) {
                // no secret yet, we need to generate a secret
                newClient = clientService.generateClientSecret(newClient)
            }
        } else if (newClient.tokenEndpointAuthMethod == AuthMethod.PRIVATE_KEY) {
            if (Strings.isNullOrEmpty(newClient.jwksUri) && newClient.jwks == null) {
                throw ValidationException("invalid_client_metadata", "JWK Set URI required when using private key authentication", HttpStatus.BAD_REQUEST)
            }

            newClient.clientSecret = null
        } else if (newClient.tokenEndpointAuthMethod == AuthMethod.NONE) {
            newClient.clientSecret = null
        } else {
            throw ValidationException("invalid_client_metadata", "Unknown authentication method", HttpStatus.BAD_REQUEST)
        }
        return newClient
    }

    private fun fetchValidRegistrationToken(
        auth: OAuth2Authentication,
        client: ClientDetailsEntity
    ): OAuth2AccessTokenEntity? {
        val details = auth.details as OAuth2AuthenticationDetails
        val token = tokenService.readAccessToken(details.tokenValue)

        if (config.regTokenLifeTime != null) {
            try {
                // Re-issue the token if it has been issued before [currentTime - validity]
                val validToDate = Date(System.currentTimeMillis() - config.regTokenLifeTime!! * 1000)
                if (token.jwt!!.jwtClaimsSet.issueTime.before(validToDate)) {
                    logger.info("Rotating the registration access token for " + client.clientId)
                    tokenService.revokeAccessToken(token)
                    val newToken = connectTokenService.createResourceAccessToken(client)
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
        const val URL: String = "resource"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(ProtectedResourceRegistrationEndpoint::class.java)
    }
}