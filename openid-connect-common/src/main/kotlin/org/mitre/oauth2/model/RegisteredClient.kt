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
    val client: OAuthClientDetails = ClientDetailsEntity(),
    // these fields are needed in addition to the ones in ClientDetailsEntity
    val registrationAccessToken: String? = null,
    val registrationClientUri: String? = null,
    val clientSecretExpiresAt: Date? = null,
    val clientIdIssuedAt: Date? = null,
    val source: JsonObject? = null,
) {

    fun copy(
        client: OAuthClientDetails = this.client.copy(),
        registrationAccessToken: String? = this.registrationAccessToken,
        registrationClientUri: String? = this.registrationClientUri,
        clientSecretExpiresAt: Date? = this.clientSecretExpiresAt,
        clientIdIssuedAt: Date? = this.clientIdIssuedAt,
        source: JsonObject? = this.source,
    ): RegisteredClient {
        return RegisteredClient(client, registrationAccessToken, registrationClientUri, clientSecretExpiresAt, clientIdIssuedAt, source)
    }

    val clientDescription: String
        get() = client.clientDescription

    val isAllowRefresh: Boolean get() = client.isAllowRefresh

    val isReuseRefreshToken: Boolean
        get() = client.isReuseRefreshToken

    val idTokenValiditySeconds: Int?
        get() = client.idTokenValiditySeconds

    val isDynamicallyRegistered: Boolean
        get() = client.isDynamicallyRegistered

    val isAllowIntrospection: Boolean
        get() = client.isAllowIntrospection

    val isSecretRequired: Boolean get() = client.isSecretRequired()

    val isScoped: Boolean get() = client.isScoped()

    val clientId: String?
        get() = client.getClientId()

    val clientSecret: String?
        get() = client.getClientSecret()

    val scope: Set<String>?
        get() = client.getScope()

    val grantTypes: Set<String>
        get() = client.grantTypes

    val authorizedGrantTypes: Set<String>
        get() = client.getAuthorizedGrantTypes()

    val authorities: Set<GrantedAuthority>
        get() = client.getAuthorities()

    val accessTokenValiditySeconds: Int?
        get() = client.getAccessTokenValiditySeconds()

    val refreshTokenValiditySeconds: Int?
        get() = client.getRefreshTokenValiditySeconds()

    val redirectUris: Set<String>
        get() = client.redirectUris

    val registeredRedirectUri: Set<String>?
        get() = client.getRegisteredRedirectUri()
    
    val resourceIds: Set<String>
        get() = client.getResourceIds()

    val additionalInformation: Map<String, Any>
        get() = client.getAdditionalInformation()
    
    val applicationType: OAuthClientDetails.AppType
        get() = client.applicationType

    val clientName: String?
        get() = client.clientName

    val tokenEndpointAuthMethod: OAuthClientDetails.AuthMethod?
        get() = client.tokenEndpointAuthMethod

    val subjectType: OAuthClientDetails.SubjectType?
        get() = client.subjectType

    val contacts: Set<String>?
        get() = client.contacts

    val logoUri: String?
        get() = client.logoUri

    val policyUri: String?
        get() = client.policyUri

    val clientUri: String?
        get() = client.clientUri

    val tosUri: String?
        get() = client.tosUri

    val jwksUri: String?
        get() = client.jwksUri

    val jwks: JWKSet?
        get() = client.jwks

    val sectorIdentifierUri: String?
        get() = client.sectorIdentifierUri

    val defaultMaxAge: Long?
        get() = client.defaultMaxAge

    val requireAuthTime: Boolean?
        get() = client.requireAuthTime

    val responseTypes: Set<String>
        get() = client.responseTypes

    val defaultACRvalues: Set<String>?
        get() = client.defaultACRvalues

    val initiateLoginUri: String?
        get() = client.initiateLoginUri

    val postLogoutRedirectUris: Set<String>?
        get() = client.postLogoutRedirectUris

    val requestUris: Set<String>?
        get() = client.requestUris

    val requestObjectSigningAlg: JWSAlgorithm?
        get() = client.requestObjectSigningAlg

    val userInfoSignedResponseAlg: JWSAlgorithm?
        get() = client.userInfoSignedResponseAlg

    val userInfoEncryptedResponseAlg: JWEAlgorithm?
        get() = client.userInfoEncryptedResponseAlg

    val userInfoEncryptedResponseEnc: EncryptionMethod?
        get() = client.userInfoEncryptedResponseEnc

    val idTokenSignedResponseAlg: JWSAlgorithm?
        get() = client.idTokenSignedResponseAlg

    val idTokenEncryptedResponseAlg: JWEAlgorithm?
        get() = client.idTokenEncryptedResponseAlg

    val idTokenEncryptedResponseEnc: EncryptionMethod?
        get() = client.idTokenEncryptedResponseEnc

    val tokenEndpointAuthSigningAlg: JWSAlgorithm?
        get() = client.tokenEndpointAuthSigningAlg

    val createdAt: Date?
        get() = client.createdAt

    val claimsRedirectUris: Set<String>?
        get() = client.claimsRedirectUris

    val softwareStatement: JWT?
        get() = client.softwareStatement

    val codeChallengeMethod: PKCEAlgorithm?
        get() = client.codeChallengeMethod

    val deviceCodeValiditySeconds: Int?
        get() = client.deviceCodeValiditySeconds

    val softwareId: String?
        get() = client.softwareId

    val softwareVersion: String?
        get() = client.softwareVersion

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
        @SerialName(TOKEN_ENDPOINT_AUTH_METHOD) val tokenEndpointAuthMethod: OAuthClientDetails.AuthMethod? = null,
        @SerialName(SCOPE) val scope: String? = null,
        @SerialName(GRANT_TYPES) val grantTypes: Set<String> = emptySet(),
        @SerialName(RESPONSE_TYPES) val responseTypes: Set<String> = emptySet(),
        @SerialName(POLICY_URI) val policyUri: String? = null,
        @SerialName(JWKS_URI) val jwksUri: String? = null,
        @SerialName(JWKS) val jwks: @Serializable(with = JWKSetStringConverter::class) JWKSet? = null,
        @SerialName(APPLICATION_TYPE) val applicationType: OAuthClientDetails.AppType? = null,
        @SerialName(SECTOR_IDENTIFIER_URI) val sectorIdentifierUri: String? = null,
        @SerialName(SUBJECT_TYPE) val subjectType: OAuthClientDetails.SubjectType? = null,
        @SerialName(REQUEST_OBJECT_SIGNING_ALG) val requestObjectSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(USERINFO_SIGNED_RESPONSE_ALG) val userInfoSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(USERINFO_ENCRYPTED_RESPONSE_ALG) val userInfoEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName(USERINFO_ENCRYPTED_RESPONSE_ENC) val userInfoEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName(ID_TOKEN_SIGNED_RESPONSE_ALG) val idTokenSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ALG) val idTokenEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ENC) val idTokenEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG) val tokenEndpointAuthSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName(DEFAULT_MAX_AGE) val defaultMaxAge: Long? = null,
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
                applicationType = applicationType ?: OAuthClientDetails.AppType.WEB,
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
