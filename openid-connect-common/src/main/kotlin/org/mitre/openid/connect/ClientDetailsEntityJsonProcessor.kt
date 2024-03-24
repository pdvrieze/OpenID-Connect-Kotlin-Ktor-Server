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
package org.mitre.openid.connect

import com.google.common.base.Joiner
import com.google.common.base.Splitter
import com.google.common.base.Strings
import com.google.common.collect.Sets
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTParser
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.model.RegisteredClientFields.APPLICATION_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.CLAIMS_REDIRECT_URIS
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID_ISSUED_AT
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_NAME
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_SECRET
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_SECRET_EXPIRES_AT
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_URI
import org.mitre.oauth2.model.RegisteredClientFields.CODE_CHALLENGE_METHOD
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
import org.mitre.oauth2.model.RegisteredClientFields.SCOPE_SEPARATOR
import org.mitre.oauth2.model.RegisteredClientFields.SECTOR_IDENTIFIER_URI
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_ID
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_STATEMENT
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_VERSION
import org.mitre.oauth2.model.RegisteredClientFields.SUBJECT_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.TOKEN_ENDPOINT_AUTH_METHOD
import org.mitre.oauth2.model.RegisteredClientFields.TOKEN_ENDPOINT_AUTH_SIGNING_ALG
import org.mitre.oauth2.model.RegisteredClientFields.TOS_URI
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ALG
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ENC
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_SIGNED_RESPONSE_ALG
import org.mitre.util.JsonUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.text.ParseException


/**
 * Utility class to handle the parsing and serialization of ClientDetails objects.
 *
 * @author jricher
 */
object ClientDetailsEntityJsonProcessor {
    private val logger: Logger = LoggerFactory.getLogger(ClientDetailsEntityJsonProcessor::class.java)

    private val parser = JsonParser()

    /**
     * Create an unbound ClientDetailsEntity from the given JSON string.
     *
     * @return the entity if successful, null otherwise
     */
    @JvmStatic
    fun parse(jsonString: String?): ClientDetailsEntity? {
        val jsonEl = parser.parse(jsonString)
        return parse(jsonEl)
    }

    @JvmStatic
    fun parse(jsonEl: JsonElement): ClientDetailsEntity? {
        if (jsonEl.isJsonObject) {
            val o = jsonEl.asJsonObject
            val c = ClientDetailsEntity()

            // these two fields should only be sent in the update request, and MUST match existing values
            c.clientId = JsonUtils.getAsString(o, CLIENT_ID)
            c.clientSecret = JsonUtils.getAsString(o, CLIENT_SECRET)

            // OAuth DynReg
            c.redirectUris = JsonUtils.getAsStringSet(o, REDIRECT_URIS) ?: HashSet()
            c.clientName = JsonUtils.getAsString(o, CLIENT_NAME)
            c.clientUri = JsonUtils.getAsString(o, CLIENT_URI)
            c.logoUri = JsonUtils.getAsString(o, LOGO_URI)
            c.contacts = JsonUtils.getAsStringSet(o, CONTACTS)
            c.tosUri = JsonUtils.getAsString(o, TOS_URI)

            val authMethod = JsonUtils.getAsString(o, TOKEN_ENDPOINT_AUTH_METHOD)
            if (authMethod != null) {
                c.tokenEndpointAuthMethod = AuthMethod.getByValue(authMethod)
            }

            // scope is a space-separated string
            val scope = JsonUtils.getAsString(o, SCOPE)
            if (scope != null) {
                c.scope = Sets.newHashSet<String>(Splitter.on(SCOPE_SEPARATOR).split(scope))
            }

            c.grantTypes = JsonUtils.getAsStringSet(o, GRANT_TYPES) ?: HashSet()
            c.responseTypes = JsonUtils.getAsStringSet(o, RESPONSE_TYPES) ?: HashSet()
            c.policyUri = JsonUtils.getAsString(o, POLICY_URI)
            c.jwksUri = JsonUtils.getAsString(o, JWKS_URI)

            val jwksEl = o[JWKS]
            if (jwksEl != null && jwksEl.isJsonObject) {
                try {
                    val jwks =
                        JWKSet.parse(jwksEl.toString()) // we have to pass this through Nimbus's parser as a string
                    c.jwks = jwks
                } catch (e: ParseException) {
                    logger.error("Unable to parse JWK Set for client", e)
                    return null
                }
            }

            // OIDC Additions
            val appType = JsonUtils.getAsString(o, APPLICATION_TYPE)
            if (appType != null) {
                c.applicationType = AppType.getByValue(appType)
            }

            c.sectorIdentifierUri = JsonUtils.getAsString(o, SECTOR_IDENTIFIER_URI)

            val subjectType = JsonUtils.getAsString(o, SUBJECT_TYPE)
            if (subjectType != null) {
                c.subjectType = SubjectType.getByValue(subjectType)
            }

            c.requestObjectSigningAlg = JsonUtils.getAsJwsAlgorithm(o, REQUEST_OBJECT_SIGNING_ALG)

            c.userInfoSignedResponseAlg = JsonUtils.getAsJwsAlgorithm(o, USERINFO_SIGNED_RESPONSE_ALG)
            c.userInfoEncryptedResponseAlg = JsonUtils.getAsJweAlgorithm(o, USERINFO_ENCRYPTED_RESPONSE_ALG)
            c.userInfoEncryptedResponseEnc = JsonUtils.getAsJweEncryptionMethod(o, USERINFO_ENCRYPTED_RESPONSE_ENC)

            c.idTokenSignedResponseAlg = JsonUtils.getAsJwsAlgorithm(o, ID_TOKEN_SIGNED_RESPONSE_ALG)
            c.idTokenEncryptedResponseAlg = JsonUtils.getAsJweAlgorithm(o, ID_TOKEN_ENCRYPTED_RESPONSE_ALG)
            c.idTokenEncryptedResponseEnc = JsonUtils.getAsJweEncryptionMethod(o, ID_TOKEN_ENCRYPTED_RESPONSE_ENC)

            c.tokenEndpointAuthSigningAlg = JsonUtils.getAsJwsAlgorithm(o, TOKEN_ENDPOINT_AUTH_SIGNING_ALG)

            if (o.has(DEFAULT_MAX_AGE)) {
                if (o[DEFAULT_MAX_AGE].isJsonPrimitive) {
                    c.defaultMaxAge = o[DEFAULT_MAX_AGE].asInt
                }
            }

            if (o.has(REQUIRE_AUTH_TIME)) {
                if (o[REQUIRE_AUTH_TIME].isJsonPrimitive) {
                    c.requireAuthTime = o[REQUIRE_AUTH_TIME].asBoolean
                }
            }

            c.defaultACRvalues = JsonUtils.getAsStringSet(o, DEFAULT_ACR_VALUES)
            c.initiateLoginUri = JsonUtils.getAsString(o, INITIATE_LOGIN_URI)
            c.postLogoutRedirectUris = JsonUtils.getAsStringSet(o, POST_LOGOUT_REDIRECT_URIS)
            c.requestUris = JsonUtils.getAsStringSet(o, REQUEST_URIS)

            c.claimsRedirectUris = JsonUtils.getAsStringSet(o, CLAIMS_REDIRECT_URIS)

            c.codeChallengeMethod = JsonUtils.getAsPkceAlgorithm(o, CODE_CHALLENGE_METHOD)

            c.softwareId = JsonUtils.getAsString(o, SOFTWARE_ID)
            c.softwareVersion = JsonUtils.getAsString(o, SOFTWARE_VERSION)

            // note that this does not process or validate the software statement, that's handled in other components
            val softwareStatement = JsonUtils.getAsString(o, SOFTWARE_STATEMENT)
            if (!Strings.isNullOrEmpty(softwareStatement)) {
                try {
                    val softwareStatementJwt = JWTParser.parse(softwareStatement)
                    c.softwareStatement = softwareStatementJwt
                } catch (e: ParseException) {
                    logger.warn("Error parsing software statement", e)
                    return null
                }
            }



            return c
        } else {
            return null
        }
    }

    /**
     * Parse the JSON as a RegisteredClient (useful in the dynamic client filter)
     */
    @JvmStatic
    fun parseRegistered(jsonString: String?): RegisteredClient? {
        val jsonEl = parser.parse(jsonString)
        return parseRegistered(jsonEl)
    }

    @JvmStatic
    fun parseRegistered(jsonEl: JsonElement): RegisteredClient? {
        if (jsonEl.isJsonObject) {
            val o = jsonEl.asJsonObject
            val c = parse(jsonEl)

            val rc = RegisteredClient(c!!)
            // get any fields from the registration
            rc.registrationAccessToken = JsonUtils.getAsString(o, REGISTRATION_ACCESS_TOKEN)
            rc.registrationClientUri = JsonUtils.getAsString(o, REGISTRATION_CLIENT_URI)
            rc.clientIdIssuedAt = JsonUtils.getAsDate(o, CLIENT_ID_ISSUED_AT)
            rc.clientSecretExpiresAt = JsonUtils.getAsDate(o, CLIENT_SECRET_EXPIRES_AT)

            rc.source = o

            return rc
        } else {
            return null
        }
    }

    @JvmStatic
    fun serialize(c: RegisteredClient): JsonObject? {
        if (c.source != null) {
            // if we have the original object, just use that
            return c.source
        } else {
            val o = JsonObject()

            o.addProperty(CLIENT_ID, c.clientId)
            if (c.clientSecret != null) {
                o.addProperty(CLIENT_SECRET, c.clientSecret)

                if (c.clientSecretExpiresAt == null) {
                    o.addProperty(CLIENT_SECRET_EXPIRES_AT, 0) // TODO: do we want to let secrets expire?
                } else {
                    o.addProperty(CLIENT_SECRET_EXPIRES_AT, c.clientSecretExpiresAt!!.time / 1000L)
                }
            }

            if (c.clientIdIssuedAt != null) {
                o.addProperty(CLIENT_ID_ISSUED_AT, c.clientIdIssuedAt!!.time / 1000L)
            } else if (c.createdAt != null) {
                o.addProperty(CLIENT_ID_ISSUED_AT, c.createdAt!!.time / 1000L)
            }
            if (c.registrationAccessToken != null) {
                o.addProperty(REGISTRATION_ACCESS_TOKEN, c.registrationAccessToken)
            }

            if (c.registrationClientUri != null) {
                o.addProperty(REGISTRATION_CLIENT_URI, c.registrationClientUri)
            }


            // add in all other client properties

            // OAuth DynReg
            o.add(REDIRECT_URIS, JsonUtils.getAsArray(c.redirectUris))
            o.addProperty(CLIENT_NAME, c.clientName)
            o.addProperty(CLIENT_URI, c.clientUri)
            o.addProperty(LOGO_URI, c.logoUri)
            o.add(CONTACTS, JsonUtils.getAsArray(c.contacts))
            o.addProperty(TOS_URI, c.tosUri)
            o.addProperty(TOKEN_ENDPOINT_AUTH_METHOD, if (c.tokenEndpointAuthMethod != null) c.tokenEndpointAuthMethod!!.value else null)
            o.addProperty(SCOPE, if (c.scope != null) Joiner.on(SCOPE_SEPARATOR).join(c.scope) else null)
            o.add(GRANT_TYPES, JsonUtils.getAsArray(c.grantTypes))
            o.add(RESPONSE_TYPES, JsonUtils.getAsArray(c.responseTypes))
            o.addProperty(POLICY_URI, c.policyUri)
            o.addProperty(JWKS_URI, c.jwksUri)

            // get the JWKS sub-object
            if (c.jwks != null) {
                // We have to re-parse it into GSON because Nimbus uses a different parser
                val jwks = parser.parse(c.jwks.toString())
                o.add(JWKS, jwks)
            } else {
                o.add(JWKS, null)
            }

            // OIDC Registration
            o.addProperty(APPLICATION_TYPE, if (c.applicationType != null) c.applicationType!!.value else null)
            o.addProperty(SECTOR_IDENTIFIER_URI, c.sectorIdentifierUri)
            o.addProperty(SUBJECT_TYPE, if (c.subjectType != null) c.subjectType!!.value else null)
            o.addProperty(REQUEST_OBJECT_SIGNING_ALG, if (c.requestObjectSigningAlg != null) c.requestObjectSigningAlg!!.name else null)
            o.addProperty(USERINFO_SIGNED_RESPONSE_ALG, if (c.userInfoSignedResponseAlg != null) c.userInfoSignedResponseAlg!!.name else null)
            o.addProperty(USERINFO_ENCRYPTED_RESPONSE_ALG, if (c.userInfoEncryptedResponseAlg != null) c.userInfoEncryptedResponseAlg!!.name else null)
            o.addProperty(USERINFO_ENCRYPTED_RESPONSE_ENC, if (c.userInfoEncryptedResponseEnc != null) c.userInfoEncryptedResponseEnc!!.name else null)
            o.addProperty(ID_TOKEN_SIGNED_RESPONSE_ALG, if (c.idTokenSignedResponseAlg != null) c.idTokenSignedResponseAlg!!.name else null)
            o.addProperty(ID_TOKEN_ENCRYPTED_RESPONSE_ALG, if (c.idTokenEncryptedResponseAlg != null) c.idTokenEncryptedResponseAlg!!.name else null)
            o.addProperty(ID_TOKEN_ENCRYPTED_RESPONSE_ENC, if (c.idTokenEncryptedResponseEnc != null) c.idTokenEncryptedResponseEnc!!.name else null)
            o.addProperty(TOKEN_ENDPOINT_AUTH_SIGNING_ALG, if (c.tokenEndpointAuthSigningAlg != null) c.tokenEndpointAuthSigningAlg!!.name else null)
            o.addProperty(DEFAULT_MAX_AGE, c.defaultMaxAge)
            o.addProperty(REQUIRE_AUTH_TIME, c.requireAuthTime)
            o.add(DEFAULT_ACR_VALUES, JsonUtils.getAsArray(c.defaultACRvalues))
            o.addProperty(INITIATE_LOGIN_URI, c.initiateLoginUri)
            o.add(POST_LOGOUT_REDIRECT_URIS, JsonUtils.getAsArray(c.postLogoutRedirectUris))
            o.add(REQUEST_URIS, JsonUtils.getAsArray(c.requestUris))

            o.add(CLAIMS_REDIRECT_URIS, JsonUtils.getAsArray(c.claimsRedirectUris))

            o.addProperty(CODE_CHALLENGE_METHOD, if (c.codeChallengeMethod != null) c.codeChallengeMethod!!.name else null)

            o.addProperty(SOFTWARE_ID, c.softwareId)
            o.addProperty(SOFTWARE_VERSION, c.softwareVersion)

            if (c.softwareStatement != null) {
                o.addProperty(SOFTWARE_STATEMENT, c.softwareStatement!!.serialize())
            }

            return o
        }
    }
}
