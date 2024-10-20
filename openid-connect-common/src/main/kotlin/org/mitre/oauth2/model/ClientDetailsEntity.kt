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
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.OAuthClientDetails.*
import org.mitre.oauth2.model.RegisteredClientFields.APPLICATION_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.CLAIMS_REDIRECT_URIS
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_NAME
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_SECRET
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
import org.mitre.oauth2.model.convert.*
import java.util.*
import kotlinx.serialization.Transient as KXS_Transient

/**
 * @author jricher
 *
 * @property authorities Fields to support the ClientDetails interface
 */
@Serializable
open class ClientDetailsEntity private constructor(
    override var id: Long? = null,

    /** Fields from the OAuth2 Dynamic Registration Specification  */
    @SerialName(CLIENT_ID)
    override var clientId: String? = null, // client_id

    @SerialName(CLIENT_SECRET)
    override var clientSecret: String? = null, // client_secret

    @SerialName(REDIRECT_URIS)
    override var redirectUris: Set<String> = HashSet(), // redirect_uris

    @SerialName(CLIENT_NAME)
    override var clientName: String? = null, // client_name

    @SerialName(CLIENT_URI)
    override var clientUri: String? = null, // client_uri

    @SerialName(LOGO_URI)
    override var logoUri: String? = null, // logo_uri

    @SerialName(CONTACTS)
    override var contacts: Set<String>? = null, // contacts

    @SerialName(TOS_URI)
    override var tosUri: String? = null, // tos_uri

    @SerialName(TOKEN_ENDPOINT_AUTH_METHOD)
    override var tokenEndpointAuthMethod: AuthMethod? = AuthMethod.SECRET_BASIC, // token_endpoint_auth_method

    @SerialName(SCOPE)
    override var scope: Set<String>? = HashSet(), // scope
    // TODO make the scope not null (it is not valid in the introspection endpoint original code)

    @SerialName(GRANT_TYPES)
    override var authorizedGrantTypes: Set<String> = HashSet(), // grant_types

    @SerialName(RESPONSE_TYPES)
    override var responseTypes: MutableSet<String> = HashSet(), // response_types

    @SerialName(POLICY_URI)
    override var policyUri: String? = null,

    @SerialName(JWKS_URI)
    override var jwksUri: String? = null, // URI pointer to keys

    @SerialName(JWKS)
    override var jwks: @Serializable(with = JWKSetStringConverter::class) JWKSet? = null, // public key stored by value

    @SerialName(SOFTWARE_ID)
    override var softwareId: String? = null,

    @SerialName(SOFTWARE_VERSION)
    override var softwareVersion: String? = null,

    /** Fields from OIDC Client Registration Specification  */
    @SerialName(APPLICATION_TYPE)
    override var applicationType: AppType = AppType.WEB, // application_type

    @SerialName(SECTOR_IDENTIFIER_URI)
    override var sectorIdentifierUri: String? = null, // sector_identifier_uri

    @SerialName(SUBJECT_TYPE)
    override var subjectType: SubjectType? = null, // subject_type

    @SerialName(REQUEST_OBJECT_SIGNING_ALG)
    override var requestObjectSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // request_object_signing_alg

    @SerialName(USERINFO_SIGNED_RESPONSE_ALG)
    override var userInfoSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // user_info_signed_response_alg

    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ALG)
    override var userInfoEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null, // user_info_encrypted_response_alg

    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ENC)
    override var userInfoEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null, // user_info_encrypted_response_enc

    @SerialName(ID_TOKEN_SIGNED_RESPONSE_ALG)
    override var idTokenSignedResponseAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // id_token_signed_response_alg

    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ALG)
    override var idTokenEncryptedResponseAlg: @Serializable(with = JWEAlgorithmStringConverter::class) JWEAlgorithm? = null, // id_token_encrypted_response_alg

    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ENC)
    override var idTokenEncryptedResponseEnc: @Serializable(with = JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null, // id_token_encrypted_response_enc

    @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG)
    override var tokenEndpointAuthSigningAlg: @Serializable(with = JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // token_endpoint_auth_signing_alg

    @SerialName(DEFAULT_MAX_AGE)
    override var defaultMaxAge: Long? = null, // default_max_age

    @SerialName(REQUIRE_AUTH_TIME)
    override var requireAuthTime: Boolean? = null, // require_auth_time

    @SerialName(DEFAULT_ACR_VALUES)
    override var defaultACRvalues: Set<String>? = null, // default_acr_values

    @SerialName(INITIATE_LOGIN_URI)
    override var initiateLoginUri: String? = null, // initiate_login_uri

    @SerialName(POST_LOGOUT_REDIRECT_URIS)
    override var postLogoutRedirectUris: Set<String>? = null, // post_logout_redirect_uris

    @SerialName(REQUEST_URIS)
    override var requestUris: Set<String>? = null, // request_uris

    /**
     * Human-readable long description of the client (optional)
     */
    @KXS_Transient
    override var clientDescription: String = "", // human-readable description

    @KXS_Transient
    override var isReuseRefreshToken: Boolean = true, // do we let someone reuse a refresh token?

    @KXS_Transient
    override var isDynamicallyRegistered: Boolean = false, // was this client dynamically registered?

    @KXS_Transient
    override var isAllowIntrospection: Boolean = false, // do we let this client call the introspection endpoint?

    @KXS_Transient
    override var idTokenValiditySeconds: Int = DEFAULT_ID_TOKEN_VALIDITY_SECONDS, //timeout for id tokens

    @KXS_Transient
    override var createdAt: Date? = null, // time the client was created

    @KXS_Transient
    override var isClearAccessTokensOnRefresh: Boolean = true, // do we clear access tokens on refresh?

    @KXS_Transient
    override var deviceCodeValiditySeconds: Int? = null, // timeout for device codes

    /** fields for UMA  */
    @SerialName(CLAIMS_REDIRECT_URIS)
    override var claimsRedirectUris: Set<String>? = null,

    /** Software statement  */
    @SerialName(SOFTWARE_STATEMENT)
    override var softwareStatement: @Serializable(with = JWTStringConverter::class) JWT? = null,

    /** PKCE  */
    @SerialName(CODE_CHALLENGE_METHOD)
    override var codeChallengeMethod: @Serializable PKCEAlgorithm? = null,

//    @KXS_Transient
    override var accessTokenValiditySeconds: Int? = 0,
//    @KXS_Transient
    override var authorities: Set<GrantedAuthority> = HashSet(), // = HashSet()
//    @KXS_Transient
    override var refreshTokenValiditySeconds: Int? = 0, // 0
//    @KXS_Transient
    override var resourceIds: Set<String> = HashSet(),
    @KXS_Transient
    override val additionalInformation: Map<String, Any> = HashMap(),
    @KXS_Transient
    private val dummy: Unit = Unit,
) : OAuthClientDetails/*, SpringClientDetails*/ {

    constructor(
        id: Long? = null,
        clientId: String? = null, // client_id
        clientSecret: String? = null, // client_secret
        redirectUris: Set<String> = HashSet(), // redirect_uris
        clientName: String? = null, // client_name
        clientUri: String? = null, // client_uri
        logoUri: String? = null, // logo_uri
        contacts: Set<String>? = null, // contacts
        tosUri: String? = null, // tos_uri
        tokenEndpointAuthMethod: AuthMethod? = AuthMethod.SECRET_BASIC, // token_endpoint_auth_method
        scope: Set<String>? = HashSet(), // scope
        authorizedGrantTypes: Set<String> = HashSet(), // grant_types
        responseTypes: MutableSet<String> = HashSet(), // response_types
        policyUri: String? = null,
        jwksUri: String? = null, // URI pointer to keys
        jwks: JWKSet? = null, // public key stored by value
        softwareId: String? = null,
        softwareVersion: String? = null,
        applicationType: AppType = AppType.WEB, // application_type
        sectorIdentifierUri: String? = null, // sector_identifier_uri
        subjectType: SubjectType? = null, // subject_type
        requestObjectSigningAlg: JWSAlgorithm? = null, // request_object_signing_alg
        userInfoSignedResponseAlg: JWSAlgorithm? = null, // user_info_signed_response_alg
        userInfoEncryptedResponseAlg: JWEAlgorithm? = null, // user_info_encrypted_response_alg
        userInfoEncryptedResponseEnc: EncryptionMethod? = null, // user_info_encrypted_response_enc
        idTokenSignedResponseAlg: JWSAlgorithm? = null, // id_token_signed_response_alg
        idTokenEncryptedResponseAlg: JWEAlgorithm? = null, // id_token_encrypted_response_alg
        idTokenEncryptedResponseEnc: EncryptionMethod? = null, // id_token_encrypted_response_enc
        tokenEndpointAuthSigningAlg: JWSAlgorithm? = null, // token_endpoint_auth_signing_alg
        defaultMaxAge: Long? = null, // default_max_age
        requireAuthTime: Boolean? = null, // require_auth_time
        defaultACRvalues: Set<String>? = null, // default_acr_values
        initiateLoginUri: String? = null, // initiate_login_uri
        postLogoutRedirectUris: Set<String>? = null, // post_logout_redirect_uris
        requestUris: Set<String>? = null, // request_uris
        clientDescription: String = "", // human-readable description
        isReuseRefreshToken: Boolean = true, // do we let someone reuse a refresh token?
        isDynamicallyRegistered: Boolean = false, // was this client dynamically registered?
        isAllowIntrospection: Boolean = false, // do we let this client call the introspection endpoint?
        idTokenValiditySeconds: Int = DEFAULT_ID_TOKEN_VALIDITY_SECONDS, //timeout for id tokens
        createdAt: Date? = null, // time the client was created
        isClearAccessTokensOnRefresh: Boolean = true, // do we clear access tokens on refresh?
        deviceCodeValiditySeconds: Int? = null, // timeout for device codes
        claimsRedirectUris: Set<String>? = null,
        softwareStatement: JWT? = null,
        codeChallengeMethod: PKCEAlgorithm? = null,
        accessTokenValiditySeconds: Int? = 0,
        authorities: Set<GrantedAuthority>, // = HashSet()
        refreshTokenValiditySeconds: Int?, // 0
        resourceIds: Set<String>, // = HashSet()
        additionalInformation: Map<String, Any>, // = HashMap()
    ) : this(
        id = id,
        clientId = clientId,
        clientSecret = clientSecret,
        redirectUris = redirectUris,
        clientName = clientName,
        clientUri = clientUri,
        logoUri = logoUri,
        contacts = contacts,
        tosUri = tosUri,
        tokenEndpointAuthMethod = tokenEndpointAuthMethod,
        scope = scope,
        authorizedGrantTypes = authorizedGrantTypes,
        responseTypes = responseTypes,
        policyUri = policyUri,
        jwksUri = jwksUri,
        jwks = jwks,
        softwareId = softwareId,
        softwareVersion = softwareVersion,
        applicationType = applicationType,
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
        clientDescription = clientDescription,
        isReuseRefreshToken = isReuseRefreshToken,
        isDynamicallyRegistered = isDynamicallyRegistered,
        isAllowIntrospection = isAllowIntrospection,
        idTokenValiditySeconds = if (idTokenValiditySeconds>0) idTokenValiditySeconds else 5*60,
        createdAt = createdAt,
        isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh,
        deviceCodeValiditySeconds = deviceCodeValiditySeconds,
        claimsRedirectUris = claimsRedirectUris,
        softwareStatement = softwareStatement,
        codeChallengeMethod = codeChallengeMethod,
        accessTokenValiditySeconds = accessTokenValiditySeconds,
        authorities = authorities,
        refreshTokenValiditySeconds = refreshTokenValiditySeconds,
        resourceIds = resourceIds,
        additionalInformation = additionalInformation,
        dummy = Unit,
    )

    constructor(builder: Builder): this(
        id = builder.id,
        clientId = builder.clientId,
        clientSecret = builder.clientSecret,
        redirectUris = builder.redirectUris,
        clientName = builder.clientName,
        clientUri = builder.clientUri,
        logoUri = builder.logoUri,
        contacts = builder.contacts,
        tosUri = builder.tosUri,
        tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod,
        scope = builder.scope?.toHashSet(),
        authorizedGrantTypes = builder.authorizedGrantTypes,
        responseTypes = builder.responseTypes,
        policyUri = builder.policyUri,
        jwksUri = builder.jwksUri,
        jwks = builder.jwks,
        softwareId = builder.softwareId,
        softwareVersion = builder.softwareVersion,
        applicationType = builder.applicationType,
        sectorIdentifierUri = builder.sectorIdentifierUri,
        subjectType = builder.subjectType,
        requestObjectSigningAlg = builder.requestObjectSigningAlg,
        userInfoSignedResponseAlg = builder.userInfoSignedResponseAlg,
        userInfoEncryptedResponseAlg = builder.userInfoEncryptedResponseAlg,
        userInfoEncryptedResponseEnc = builder.userInfoEncryptedResponseEnc,
        idTokenSignedResponseAlg = builder.idTokenSignedResponseAlg,
        idTokenEncryptedResponseAlg = builder.idTokenEncryptedResponseAlg,
        idTokenEncryptedResponseEnc = builder.idTokenEncryptedResponseEnc,
        tokenEndpointAuthSigningAlg = builder.tokenEndpointAuthSigningAlg,
        defaultMaxAge = builder.defaultMaxAge,
        requireAuthTime = builder.requireAuthTime,
        defaultACRvalues = builder.defaultACRvalues,
        initiateLoginUri = builder.initiateLoginUri,
        postLogoutRedirectUris = builder.postLogoutRedirectUris,
        requestUris = builder.requestUris,
        clientDescription = builder.clientDescription,
        isReuseRefreshToken = builder.isReuseRefreshToken,
        isDynamicallyRegistered = builder.isDynamicallyRegistered,
        isAllowIntrospection = builder.isAllowIntrospection,
        idTokenValiditySeconds = builder.idTokenValiditySeconds ?: DEFAULT_ID_TOKEN_VALIDITY_SECONDS,
        createdAt = builder.createdAt,
        isClearAccessTokensOnRefresh = builder.isClearAccessTokensOnRefresh,
        deviceCodeValiditySeconds = builder.deviceCodeValiditySeconds,
        claimsRedirectUris = builder.claimsRedirectUris,
        softwareStatement = builder.softwareStatement,
        codeChallengeMethod = builder.codeChallengeMethod,
        accessTokenValiditySeconds = builder.accessTokenValiditySeconds,
        authorities = builder.authorities,
        refreshTokenValiditySeconds = builder.refreshTokenValiditySeconds,
        resourceIds = builder.resourceIds,
        additionalInformation = builder.additionalInformation,
        dummy = Unit,
    )

    override fun withId(id: Long): OAuthClientDetails {
        return copy(id = id)
    }

    override fun copy(
        id: Long?,
        clientId: String?,
        clientSecret: String?,
        redirectUris: Set<String>,
        clientName: String?,
        clientUri: String?,
        logoUri: String?,
        contacts: Set<String>?,
        tosUri: String?,
        tokenEndpointAuthMethod: AuthMethod?,
        scope: Set<String>?,
        authorizedGrantTypes: Set<String>,
        responseTypes: Set<String>,
        policyUri: String?,
        jwksUri: String?,
        jwks: JWKSet?,
        softwareId: String?,
        softwareVersion: String?,
        applicationType: AppType,
        sectorIdentifierUri: String?,
        subjectType: SubjectType?,
        requestObjectSigningAlg: JWSAlgorithm?,
        userInfoSignedResponseAlg: JWSAlgorithm?,
        userInfoEncryptedResponseAlg: JWEAlgorithm?,
        userInfoEncryptedResponseEnc: EncryptionMethod?,
        idTokenSignedResponseAlg: JWSAlgorithm?,
        idTokenEncryptedResponseAlg: JWEAlgorithm?,
        idTokenEncryptedResponseEnc: EncryptionMethod?,
        tokenEndpointAuthSigningAlg: JWSAlgorithm?,
        defaultMaxAge: Long?,
        requireAuthTime: Boolean?,
        defaultACRvalues: Set<String>?,
        initiateLoginUri: String?,
        postLogoutRedirectUris: Set<String>?,
        requestUris: Set<String>?,
        clientDescription: String,
        isReuseRefreshToken: Boolean,
        isDynamicallyRegistered: Boolean,
        isAllowIntrospection: Boolean,
        idTokenValiditySeconds: Int?,
        createdAt: Date?,
        isClearAccessTokensOnRefresh: Boolean,
        deviceCodeValiditySeconds: Int?,
        claimsRedirectUris: Set<String>?,
        softwareStatement: JWT?,
        codeChallengeMethod: PKCEAlgorithm?,
        accessTokenValiditySeconds: Int?,
        refreshTokenValiditySeconds: Int?,
        authorities: Set<GrantedAuthority>,
        resourceIds: Set<String>,
        additionalInformation: Map<String, Any>,
    ): ClientDetailsEntity {
        return ClientDetailsEntity(
            id = id,
            clientId = clientId,
            clientSecret = clientSecret,
            redirectUris = redirectUris,
            clientName = clientName,
            clientUri = clientUri,
            logoUri = logoUri,
            contacts = contacts,
            tosUri = tosUri,
            tokenEndpointAuthMethod = tokenEndpointAuthMethod,
            scope = scope?.toHashSet(),
            authorizedGrantTypes = authorizedGrantTypes.toHashSet(),
            responseTypes = responseTypes.toHashSet(),
            policyUri = policyUri,
            jwksUri = jwksUri,
            jwks = jwks,
            softwareId = softwareId,
            softwareVersion = softwareVersion,
            applicationType = applicationType,
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
            clientDescription = clientDescription,
            isReuseRefreshToken = isReuseRefreshToken,
            isDynamicallyRegistered = isDynamicallyRegistered,
            isAllowIntrospection = isAllowIntrospection,
            idTokenValiditySeconds = idTokenValiditySeconds ?: DEFAULT_ID_TOKEN_VALIDITY_SECONDS,
            createdAt = createdAt,
            isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh,
            deviceCodeValiditySeconds = deviceCodeValiditySeconds,
            claimsRedirectUris = claimsRedirectUris,
            softwareStatement = softwareStatement,
            codeChallengeMethod = codeChallengeMethod,
            accessTokenValiditySeconds = accessTokenValiditySeconds,
            authorities = authorities,
            refreshTokenValiditySeconds = refreshTokenValiditySeconds,
            resourceIds = resourceIds.toSet(),
            additionalInformation = additionalInformation.toMap(),
        )
    }

    protected open fun prePersist() {
        // make sure that ID tokens always time out, default to 5 minutes
        if (idTokenValiditySeconds <=0 ) {
            idTokenValiditySeconds = DEFAULT_ID_TOKEN_VALIDITY_SECONDS
        }
    }

    override val isAllowRefresh: Boolean get() = super.isAllowRefresh


    override val isSecretRequired: Boolean
        get() = super.isSecretRequired

    /**
     * If the scope list is not null or empty, then this client has been scoped.
     */
    override val isScoped: Boolean
        get() = super.isScoped

    /**
     * @param clientId The OAuth2 client_id, must be unique to this client
     */
    fun setClientId(clientId: String?, dummy: Unit = Unit) {
        this.clientId = clientId
    }

    /**
     * @param clientSecret the OAuth2 client_secret (optional)
     */
    fun setClientSecret(clientSecret: String?, dummy: Unit = Unit) {
        this.clientSecret = clientSecret
    }


    /**
     * @param scope the set of scopes allowed to be issued to this client
     */
    fun setScope(scope: Set<String>?, dummy: Unit = Unit) {
        this.scope = scope?.toHashSet() ?: hashSetOf()
    }


    /**
     * @param authorities the Spring Security authorities this client is given
     */
    fun setAuthorities(authorities: Set<GrantedAuthority>, dummy: Unit = Unit) {
        this.authorities = authorities
    }

    fun setAccessTokenValiditySeconds(accessTokenValiditySeconds: Int?, dummy: Unit = Unit) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds
    }

    /**
     * @param refreshTokenTimeout Lifetime of refresh tokens, in seconds (optional - leave null for no timeout)
     */
    fun setRefreshTokenValiditySeconds(refreshTokenValiditySeconds: Int?, dummy: Unit = Unit) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds
    }



    fun setResourceIds(resourceIds: Set<String>, dummy: Unit = Unit) {
        this.resourceIds = resourceIds
    }


    override fun builder(): Builder = Builder(this)

    class Builder(
        override var id: Long? = null,
        override var clientId: String? = null,
        override var clientSecret: String? = null,
        override var scope: MutableSet<String>? = hashSetOf(),
        override var authorizedGrantTypes: MutableSet<String> = hashSetOf(),
        override var tokenEndpointAuthMethod: AuthMethod? = null,
        override var redirectUris: MutableSet<String> = hashSetOf(),
        override var clientName: String? = null,
        override var clientUri: String? = null,
        override var logoUri: String? = null,
        override var contacts: Set<String>? = null,
        override var tosUri: String? = null,
        override var responseTypes: MutableSet<String> = hashSetOf(),
        override var policyUri: String? = null,
        override var jwksUri: String? = null,
        override var jwks: JWKSet? = null,
        override var softwareId: String? = null,
        override var softwareVersion: String? = null,
        override var applicationType: AppType = AppType.WEB,
        override var sectorIdentifierUri: String? = null,
        override var subjectType: SubjectType? = null,
        override var requestObjectSigningAlg: JWSAlgorithm? = null,
        override var userInfoSignedResponseAlg: JWSAlgorithm? = null,
        override var userInfoEncryptedResponseAlg: JWEAlgorithm? = null,
        override var userInfoEncryptedResponseEnc: EncryptionMethod? = null,
        override var idTokenSignedResponseAlg: JWSAlgorithm? = null,
        override var idTokenEncryptedResponseAlg: JWEAlgorithm? = null,
        override var idTokenEncryptedResponseEnc: EncryptionMethod? = null,
        override var tokenEndpointAuthSigningAlg: JWSAlgorithm? = null,
        override var defaultMaxAge: Long? = null,
        override var requireAuthTime: Boolean? = null,
        override var defaultACRvalues: MutableSet<String>? = null,
        override var initiateLoginUri: String? = null,
        override var postLogoutRedirectUris: MutableSet<String>? = null,
        override var requestUris: MutableSet<String>? = null,
        override var clientDescription: String = "",
        override var isReuseRefreshToken: Boolean = true,
        override var isDynamicallyRegistered: Boolean = false,
        override var isAllowIntrospection: Boolean = false,
        override var idTokenValiditySeconds: Int? = null,
        override var createdAt: Date? = null,
        override var isClearAccessTokensOnRefresh: Boolean = true,
        override var deviceCodeValiditySeconds: Int? = null,
        override var claimsRedirectUris: MutableSet<String>? = null,
        override var softwareStatement: JWT? = null,
        override var codeChallengeMethod: PKCEAlgorithm? = null,
        var accessTokenValiditySeconds: Int? = null,
        var refreshTokenValiditySeconds: Int? = null,
        var authorities: MutableSet<GrantedAuthority> = hashSetOf(),
        var resourceIds: MutableSet<String> = HashSet(),
        var additionalInformation: MutableMap<String, Any> = HashMap(),
    ): OAuthClientDetails.Builder {

        constructor(entity: OAuthClientDetails) :this(
            id = entity.id,
            clientId = entity.clientId,
            clientSecret = entity.clientSecret,
            scope = entity.scope?.toHashSet(),
            authorizedGrantTypes = entity.authorizedGrantTypes.toHashSet(),
            tokenEndpointAuthMethod = entity.tokenEndpointAuthMethod,
            redirectUris = entity.redirectUris.toHashSet(),
            clientName = entity.clientName,
            clientUri = entity.clientUri,
            logoUri = entity.logoUri,
            contacts = entity.contacts,
            tosUri = entity.tosUri,
            responseTypes = entity.responseTypes.toHashSet(),
            policyUri = entity.policyUri,
            jwksUri = entity.jwksUri,
            jwks = entity.jwks,
            softwareId = entity.softwareId,
            softwareVersion = entity.softwareVersion,
            applicationType = entity.applicationType,
            sectorIdentifierUri = entity.sectorIdentifierUri,
            subjectType = entity.subjectType,
            requestObjectSigningAlg = entity.requestObjectSigningAlg,
            userInfoSignedResponseAlg = entity.userInfoSignedResponseAlg,
            userInfoEncryptedResponseAlg = entity.userInfoEncryptedResponseAlg,
            userInfoEncryptedResponseEnc = entity.userInfoEncryptedResponseEnc,
            idTokenSignedResponseAlg = entity.idTokenSignedResponseAlg,
            idTokenEncryptedResponseAlg = entity.idTokenEncryptedResponseAlg,
            idTokenEncryptedResponseEnc = entity.idTokenEncryptedResponseEnc,
            tokenEndpointAuthSigningAlg = entity.tokenEndpointAuthSigningAlg,
            defaultMaxAge = entity.defaultMaxAge,
            requireAuthTime = entity.requireAuthTime,
            defaultACRvalues = entity.defaultACRvalues?.toHashSet(),
            initiateLoginUri = entity.initiateLoginUri,
            postLogoutRedirectUris = entity.postLogoutRedirectUris?.toHashSet(),
            requestUris = entity.requestUris?.toHashSet(),
            clientDescription = entity.clientDescription,
            isReuseRefreshToken = entity.isReuseRefreshToken,
            isDynamicallyRegistered = entity.isDynamicallyRegistered,
            isAllowIntrospection = entity.isAllowIntrospection,
            idTokenValiditySeconds = entity.idTokenValiditySeconds,
            createdAt = entity.createdAt,
            isClearAccessTokensOnRefresh = entity.isClearAccessTokensOnRefresh,
            accessTokenValiditySeconds = entity.accessTokenValiditySeconds,
            refreshTokenValiditySeconds = entity.refreshTokenValiditySeconds,
            authorities = entity.authorities.toHashSet(),
            resourceIds = entity.resourceIds.toHashSet(), // = HashSet()
            additionalInformation = entity.additionalInformation.toMutableMap(), // = HashMap()
        )

        override fun build(): ClientDetailsEntity {
            return ClientDetailsEntity(this)
        }
    }

    companion object {
        fun from(original: OAuthClientDetails): ClientDetailsEntity = when (original) {
            is ClientDetailsEntity -> original
            else -> ClientDetailsEntity(
                id = original.id,
                clientId = original.clientId,
                clientSecret = original.clientSecret,
                redirectUris = original.redirectUris,
                clientName = original.clientName,
                clientUri = original.clientUri,
                logoUri = original.logoUri,
                contacts = original.contacts,
                tosUri = original.tosUri,
                tokenEndpointAuthMethod = original.tokenEndpointAuthMethod,
                scope = original.scope?.toHashSet(),
                authorizedGrantTypes = original.authorizedGrantTypes.toHashSet(),
                responseTypes = original.responseTypes.toHashSet(),
                policyUri = original.policyUri,
                jwksUri = original.jwksUri,
                jwks = original.jwks,
                softwareId = original.softwareId,
                softwareVersion = original.softwareVersion,
                applicationType = original.applicationType,
                sectorIdentifierUri = original.sectorIdentifierUri,
                subjectType = original.subjectType,
                requestObjectSigningAlg = original.requestObjectSigningAlg,
                userInfoSignedResponseAlg = original.userInfoSignedResponseAlg,
                userInfoEncryptedResponseAlg = original.userInfoEncryptedResponseAlg,
                userInfoEncryptedResponseEnc = original.userInfoEncryptedResponseEnc,
                idTokenSignedResponseAlg = original.idTokenSignedResponseAlg,
                idTokenEncryptedResponseAlg = original.idTokenEncryptedResponseAlg,
                idTokenEncryptedResponseEnc = original.idTokenEncryptedResponseEnc,
                tokenEndpointAuthSigningAlg = original.tokenEndpointAuthSigningAlg,
                defaultMaxAge = original.defaultMaxAge,
                requireAuthTime = original.requireAuthTime,
                defaultACRvalues = original.defaultACRvalues,
                initiateLoginUri = original.initiateLoginUri,
                postLogoutRedirectUris = original.postLogoutRedirectUris,
                requestUris = original.requestUris,
                clientDescription = original.clientDescription,
                isReuseRefreshToken = original.isReuseRefreshToken,
                isDynamicallyRegistered = original.isDynamicallyRegistered,
                isAllowIntrospection = original.isAllowIntrospection,
                idTokenValiditySeconds = original.idTokenValiditySeconds ?: DEFAULT_ID_TOKEN_VALIDITY_SECONDS,
                createdAt = original.createdAt,
                isClearAccessTokensOnRefresh = original.isClearAccessTokensOnRefresh,
                deviceCodeValiditySeconds = original.deviceCodeValiditySeconds,
                claimsRedirectUris = original.claimsRedirectUris,
                softwareStatement = original.softwareStatement,
                codeChallengeMethod = original.codeChallengeMethod,
                accessTokenValiditySeconds = original.accessTokenValiditySeconds,
                authorities = original.authorities,
                refreshTokenValiditySeconds = original.refreshTokenValiditySeconds,
                resourceIds = original.resourceIds,
                additionalInformation = original.additionalInformation,
            ).also {
                it.setAuthorities(original.authorities)
            }
        }

        const val QUERY_BY_CLIENT_ID: String = "ClientDetailsEntity.getByClientId"
        const val QUERY_ALL: String = "ClientDetailsEntity.findAll"

        const val PARAM_CLIENT_ID: String = "clientId"

        private const val DEFAULT_ID_TOKEN_VALIDITY_SECONDS = 600

        private const val serialVersionUID = -1617727085733786296L
    }
}
