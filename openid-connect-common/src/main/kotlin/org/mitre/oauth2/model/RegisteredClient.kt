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
package org.mitre.oauth2.model

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import org.mitre.oauth2.model.ClientDetailsEntity.*
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
import org.mitre.oauth2.model.convert.EpochInstant
import org.mitre.oauth2.model.convert.JWEAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWEEncryptionMethodStringConverter
import org.mitre.oauth2.model.convert.JWKSetStringConverter
import org.mitre.oauth2.model.convert.JWSAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.springframework.security.core.GrantedAuthority
import java.util.*

/**
 * @author jricher
 */
@Serializable(RegisteredClient.Companion::class)
class RegisteredClient(
    var client: ClientDetailsEntity = ClientDetailsEntity(),// these fields are needed in addition to the ones in ClientDetailsEntity
    var registrationAccessToken: String? = null,
    var registrationClientUri: String? = null,
    var clientSecretExpiresAt: Date? = null,
    var clientIdIssuedAt: Date? = null,
    var source: JsonObject? = null,
) {

    var clientDescription: String
        get() = client.clientDescription
        set(clientDescription) {
            client.clientDescription = clientDescription
        }

    val isAllowRefresh: Boolean get() = client.isAllowRefresh

    var isReuseRefreshToken: Boolean
        get() = client.isReuseRefreshToken
        set(reuseRefreshToken) {
            client.isReuseRefreshToken = reuseRefreshToken
        }

    var idTokenValiditySeconds: Int?
        get() = client.idTokenValiditySeconds
        set(idTokenValiditySeconds) {
            client.idTokenValiditySeconds = idTokenValiditySeconds
        }

    var isDynamicallyRegistered: Boolean
        get() = client.isDynamicallyRegistered
        set(dynamicallyRegistered) {
            client.isDynamicallyRegistered = dynamicallyRegistered
        }

    var isAllowIntrospection: Boolean
        get() = client.isAllowIntrospection
        set(allowIntrospection) {
            client.isAllowIntrospection = allowIntrospection
        }

    val isSecretRequired: Boolean get() = client.isSecretRequired

    val isScoped: Boolean get() = client.isScoped

    var clientId: String?
        get() = client.clientId
        set(clientId) {
            client.clientId = clientId
        }

    var clientSecret: String?
        get() = client.clientSecret
        set(clientSecret) {
            client.clientSecret = clientSecret
        }

    var scope: Set<String>?
        get() = client.scope
        set(scope) {
            client.setScope(scope ?: emptySet())
        }

    var grantTypes: Set<String>
        get() = client.grantTypes
        set(grantTypes) {
            client.grantTypes = grantTypes.toMutableSet()
        }

    val authorizedGrantTypes: Set<String>
        get() = client.authorizedGrantTypes

    var authorities: Set<GrantedAuthority>
        get() = client.authorities
        set(authorities) {
            client.authorities = authorities
        }

    var accessTokenValiditySeconds: Int?
        get() = client.accessTokenValiditySeconds
        set(accessTokenValiditySeconds) {
            client.accessTokenValiditySeconds = accessTokenValiditySeconds
        }

    var refreshTokenValiditySeconds: Int?
        get() = client.refreshTokenValiditySeconds
        set(refreshTokenValiditySeconds) {
            client.refreshTokenValiditySeconds = refreshTokenValiditySeconds
        }

    var redirectUris: Set<String>
        get() = client.redirectUris
        set(redirectUris) {
            client.redirectUris = redirectUris
        }

    val registeredRedirectUri: Set<String>?
        get() = client.registeredRedirectUri
    
    var resourceIds: Set<String>
        get() = client.resourceIds
        set(resourceIds) {
            client.resourceIds = resourceIds
        }
    
    val additionalInformation: Map<String, Any>
        get() = client.additionalInformation
    
    var applicationType: AppType
        get() = client.applicationType
        set(applicationType) {
            client.applicationType = applicationType
        }

    var clientName: String?
        get() = client.clientName
        set(clientName) {
            client.clientName = clientName
        }

    var tokenEndpointAuthMethod: AuthMethod?
        get() = client.tokenEndpointAuthMethod
        set(tokenEndpointAuthMethod) {
            client.tokenEndpointAuthMethod = tokenEndpointAuthMethod!!
        }

    var subjectType: SubjectType?
        get() = client.subjectType
        set(subjectType) {
            client.subjectType = subjectType
        }

    var contacts: Set<String>?
        get() = client.contacts
        set(contacts) {
            client.contacts = contacts
        }

    var logoUri: String?
        get() = client.logoUri
        set(logoUri) {
            client.logoUri = logoUri
        }

    var policyUri: String?
        get() = client.policyUri
        set(policyUri) { client.policyUri = policyUri }

    var clientUri: String?
        get() = client.clientUri
        set(clientUri) { client.clientUri = clientUri }

    var tosUri: String?
        get() = client.tosUri
        set(tosUri) { client.tosUri = tosUri }

    var jwksUri: String?
        get() = client.jwksUri
        set(jwksUri) { client.jwksUri = jwksUri }

    var jwks: JWKSet?
        get() = client.jwks
        set(jwks) {
            client.jwks = jwks
        }

    var sectorIdentifierUri: String?
        get() = client.sectorIdentifierUri
        set(sectorIdentifierUri) { client.sectorIdentifierUri = sectorIdentifierUri }

    var defaultMaxAge: Int?
        get() = client.defaultMaxAge
        set(defaultMaxAge) { client.defaultMaxAge = defaultMaxAge }

    var requireAuthTime: Boolean?
        get() = client.requireAuthTime
        set(requireAuthTime) { client.requireAuthTime = requireAuthTime }

    var responseTypes: Set<String>
        get() = client.responseTypes
        set(responseTypes) { client.responseTypes = responseTypes.toHashSet() }

    var defaultACRvalues: Set<String>?
        get() = client.defaultACRvalues
        set(defaultACRvalues) { client.defaultACRvalues = defaultACRvalues }

    var initiateLoginUri: String?
        get() = client.initiateLoginUri
        set(initiateLoginUri) { client.initiateLoginUri = initiateLoginUri }

    var postLogoutRedirectUris: Set<String>?
        get() = client.postLogoutRedirectUris
        set(postLogoutRedirectUri) { client.postLogoutRedirectUris = postLogoutRedirectUri }

    var requestUris: Set<String>?
        get() = client.requestUris
        set(requestUris) {
            client.requestUris = requestUris
        }

    var requestObjectSigningAlg: JWSAlgorithm?
        get() = client.requestObjectSigningAlg
        set(requestObjectSigningAlg) {
            client.requestObjectSigningAlg = requestObjectSigningAlg
        }

    var userInfoSignedResponseAlg: JWSAlgorithm?
        get() = client.userInfoSignedResponseAlg
        set(userInfoSignedResponseAlg) {
            client.userInfoSignedResponseAlg = userInfoSignedResponseAlg
        }

    var userInfoEncryptedResponseAlg: JWEAlgorithm?
        get() = client.userInfoEncryptedResponseAlg
        set(userInfoEncryptedResponseAlg) {
            client.userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg
        }

    var userInfoEncryptedResponseEnc: EncryptionMethod?
        get() = client.userInfoEncryptedResponseEnc
        set(userInfoEncryptedResponseEnc) {
            client.userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc
        }

    var idTokenSignedResponseAlg: JWSAlgorithm?
        get() = client.idTokenSignedResponseAlg
        set(idTokenSignedResponseAlg) {
            client.idTokenSignedResponseAlg = idTokenSignedResponseAlg
        }

    var idTokenEncryptedResponseAlg: JWEAlgorithm?
        get() = client.idTokenEncryptedResponseAlg
        set(idTokenEncryptedResponseAlg) {
            client.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg
        }

    var idTokenEncryptedResponseEnc: EncryptionMethod?
        get() = client.idTokenEncryptedResponseEnc
        set(idTokenEncryptedResponseEnc) {
            client.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc
        }

    var tokenEndpointAuthSigningAlg: JWSAlgorithm?
        get() = client.tokenEndpointAuthSigningAlg
        set(tokenEndpointAuthSigningAlg) {
            client.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg
        }

    var createdAt: Date?
        get() = client.createdAt?.let { it }
        set(createdAt) {
            client.createdAt = createdAt
        }

    var claimsRedirectUris: Set<String>?
        get() = client.claimsRedirectUris
        set(claimsRedirectUris) {
            client.claimsRedirectUris = claimsRedirectUris
        }

    var softwareStatement: JWT?
        get() = client.softwareStatement
        set(softwareStatement) {
            client.softwareStatement = softwareStatement
        }

    var codeChallengeMethod: PKCEAlgorithm?
        get() = client.codeChallengeMethod
        set(codeChallengeMethod) {
            client.codeChallengeMethod = codeChallengeMethod
        }

    var deviceCodeValiditySeconds: Int?
        get() = client.deviceCodeValiditySeconds
        set(deviceCodeValiditySeconds) {
            client.deviceCodeValiditySeconds = deviceCodeValiditySeconds
        }

    var softwareId: String?
        get() = client.softwareId
        set(softwareId) {
            client.softwareId = softwareId
        }

    var softwareVersion: String?
        get() = client.softwareVersion
        set(softwareVersion) {
            client.softwareVersion = softwareVersion
        }

    @Serializable
    private class SerialDelegate(
        @SerialName(CLIENT_ID) val clientId: String? = null,
        @SerialName(CLIENT_SECRET) val clientSecret: String? = null,
        @SerialName(CLIENT_SECRET_EXPIRES_AT) val clientSecretExpiresAt: EpochInstant? = null,
        @SerialName(CLIENT_ID_ISSUED_AT) val clientIdIssuedAt: EpochInstant? = null,
        @SerialName(REGISTRATION_ACCESS_TOKEN) val registrationAccessToken: String? = null,
        @SerialName(REGISTRATION_CLIENT_URI) val registrationClientUri: String? = null,
        @SerialName(REDIRECT_URIS) val redirectUris: Set<String> = emptySet(),
        @SerialName(CLIENT_NAME) val clientName: String? = null,
        @SerialName(CLIENT_URI) val clientUri: String? = null,
        @SerialName(LOGO_URI) val logoUri: String? = null,
        @SerialName(CONTACTS) val contacts: Set<String>? = null,
        @SerialName(TOS_URI) val tosUri: String? = null,
        @SerialName(TOKEN_ENDPOINT_AUTH_METHOD) val tokenEndpointAuthMethod: AuthMethod? = null,
        @SerialName(SCOPE) val scope: String? = null,
        @SerialName(GRANT_TYPES) val grantTypes: Set<String> = emptySet(),
        @SerialName(RESPONSE_TYPES) val responseTypes: Set<String> = emptySet(),
        @SerialName(POLICY_URI) val policyUri: String? = null,
        @SerialName(JWKS_URI) val jwksUri: String? = null,
        @SerialName(JWKS) val jwks: @Serializable(with = JWKSetStringConverter::class) JWKSet? = null,
        @SerialName(APPLICATION_TYPE) val applicationType: AppType? = null,
        @SerialName(SECTOR_IDENTIFIER_URI) val sectorIdentifierUri: String? = null,
        @SerialName(SUBJECT_TYPE) val subjectType: SubjectType? = null,
        @SerialName(REQUEST_OBJECT_SIGNING_ALG) val requestObjectSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(USERINFO_SIGNED_RESPONSE_ALG) val userInfoSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(USERINFO_ENCRYPTED_RESPONSE_ALG) val userInfoEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName(USERINFO_ENCRYPTED_RESPONSE_ENC) val userInfoEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName(ID_TOKEN_SIGNED_RESPONSE_ALG) val idTokenSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ALG) val idTokenEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ENC) val idTokenEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG) val tokenEndpointAuthSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(DEFAULT_MAX_AGE) val defaultMaxAge: Int? = null,
        @SerialName(REQUIRE_AUTH_TIME) val requireAuthTime: Boolean? = null,
        @SerialName(DEFAULT_ACR_VALUES) val defaultACRvalues: Set<String>? = null,
        @SerialName(INITIATE_LOGIN_URI) val initiateLoginUri: String? = null,
        @SerialName(POST_LOGOUT_REDIRECT_URIS) val postLogoutRedirectUris: Set<String>? = null,
        @SerialName(REQUEST_URIS) val requestUris: Set<String>? = null,
        @SerialName(CLAIMS_REDIRECT_URIS) val claimsRedirectUris: Set<String>? = null,
        @SerialName(CODE_CHALLENGE_METHOD) val codeChallengeMethod: PKCEAlgorithm? = null,
        @SerialName(SOFTWARE_ID) val softwareId: String? = null,
        @SerialName(SOFTWARE_VERSION) val softwareVersion: String? = null,
        @SerialName(SOFTWARE_STATEMENT) val softwareStatement: @Serializable(with = JWTStringConverter::class) JWT? = null,
    ) {

        constructor(client: RegisteredClient) : this(
            clientId = client.clientId,
            clientSecret = client.clientSecret,
            clientSecretExpiresAt = client.clientSecretExpiresAt?.toInstant(),
            clientIdIssuedAt = (client.clientIdIssuedAt ?: client.createdAt)?.toInstant(),
            registrationAccessToken = client.registrationAccessToken,
            registrationClientUri = client.registrationClientUri,
            redirectUris = client.redirectUris,
            clientName = client.clientName,
            clientUri = client.clientUri,
            logoUri = client.logoUri,
            contacts = client.contacts,
            tosUri = client.tosUri,
            tokenEndpointAuthMethod = client.tokenEndpointAuthMethod,
            scope = client.scope?.joinToString(" "),
            grantTypes = client.grantTypes,
            responseTypes = client.responseTypes,
            policyUri = client.policyUri,
            jwksUri = client.jwksUri,
            jwks = client.jwks,
            applicationType = client.applicationType,
            sectorIdentifierUri = client.sectorIdentifierUri,
            subjectType = client.subjectType,
            requestObjectSigningAlg = client.requestObjectSigningAlg,
            userInfoSignedResponseAlg = client.userInfoSignedResponseAlg,
            userInfoEncryptedResponseAlg = client.userInfoEncryptedResponseAlg,
            userInfoEncryptedResponseEnc = client.userInfoEncryptedResponseEnc,
            idTokenSignedResponseAlg = client.idTokenSignedResponseAlg,
            idTokenEncryptedResponseAlg = client.idTokenEncryptedResponseAlg,
            idTokenEncryptedResponseEnc = client.idTokenEncryptedResponseEnc,
            tokenEndpointAuthSigningAlg = client.tokenEndpointAuthSigningAlg,
            defaultMaxAge = client.defaultMaxAge,
            requireAuthTime = client.requireAuthTime,
            defaultACRvalues = client.defaultACRvalues,
            initiateLoginUri = client.initiateLoginUri,
            postLogoutRedirectUris = client.postLogoutRedirectUris,
            requestUris = client.requestUris,
            claimsRedirectUris = client.claimsRedirectUris,
            codeChallengeMethod = client.codeChallengeMethod,
            softwareId = client.softwareId,
            softwareVersion = client.softwareVersion,
            softwareStatement = client.softwareStatement,
        )

        fun toClient(source: JsonObject? = null): RegisteredClient {
//            clientSecretExpiresAt = clientSecretExpiresAt,
//            clientIdIssuedAt = clientIdIssuedAt,

            val details = ClientDetailsEntity(
                clientId = clientId,
                clientSecret = clientSecret,
                createdAt = clientIdIssuedAt?.let(Date::from),
                redirectUris = redirectUris,
                clientName = clientName,
                clientUri = clientUri,
                logoUri = logoUri,
                contacts = contacts,
                tosUri = tosUri,
                tokenEndpointAuthMethod = tokenEndpointAuthMethod,
                scope = scope
                    ?.run { splitToSequence(' ').filterNotTo(HashSet()) { it.isEmpty() }}
                    ?: hashSetOf(),
                grantTypes = grantTypes.toHashSet(),
                responseTypes = responseTypes.toHashSet(),
                policyUri = policyUri,
                jwksUri = jwksUri,
                jwks = jwks,
                applicationType = applicationType ?: AppType.WEB,
                sectorIdentifierUri = sectorIdentifierUri,
                subjectType = subjectType,
                requestObjectSigningAlg = requestObjectSigningAlg,
                userInfoSignedResponseAlg = userInfoSignedResponseAlg,
                userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg,
                userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc,
                idTokenSignedResponseAlg = idTokenSignedResponseAlg,
                idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg,
                idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc,
                tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg,
                defaultMaxAge = defaultMaxAge,
                requireAuthTime = requireAuthTime,
                defaultACRvalues = defaultACRvalues,
                initiateLoginUri = initiateLoginUri,
                postLogoutRedirectUris = postLogoutRedirectUris,
                requestUris = requestUris,
                claimsRedirectUris = claimsRedirectUris,
                codeChallengeMethod = codeChallengeMethod,
                softwareId = softwareId,
                softwareVersion = softwareVersion,
                softwareStatement = softwareStatement,
            )

            return RegisteredClient(
                details,
                registrationAccessToken,
                registrationClientUri,
                clientSecretExpiresAt?.let { Date.from(it) },
                clientIdIssuedAt?.let { Date.from(it) },
                source,
            )
        }

    }

    companion object Serializer : KSerializer<RegisteredClient> {
        private val delegate = SerialDelegate.serializer()
        override val descriptor: SerialDescriptor = SerialDescriptor("org.mitre.oauth2.model.RegisteredClient", delegate.descriptor)

        override fun serialize(encoder: Encoder, value: RegisteredClient) {
            val source = value.source
            if (encoder is JsonEncoder && source is JsonObject) {
                encoder.encodeJsonElement(source)
            } else {
                delegate.serialize(encoder, SerialDelegate(value))
            }
        }

        override fun deserialize(decoder: Decoder): RegisteredClient {
            if (decoder is JsonDecoder) {
                val source  = decoder.decodeJsonElement()
                return decoder.json.decodeFromJsonElement(delegate, source).toClient(source as? JsonObject)
            } else {
                return delegate.deserialize(decoder).toClient()
            }
        }
    }
}
