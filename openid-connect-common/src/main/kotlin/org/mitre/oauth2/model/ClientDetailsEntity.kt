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
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.provider.ClientDetails
import java.util.*
import javax.persistence.*
import kotlinx.serialization.Transient as KXS_Transient
import javax.persistence.Transient as JPATransient

/**
 * @author jricher
 */
@Entity
@Table(name = "client_details")
@NamedQueries(NamedQuery(name = ClientDetailsEntity.QUERY_ALL, query = "SELECT c FROM ClientDetailsEntity c"), NamedQuery(name = ClientDetailsEntity.QUERY_BY_CLIENT_ID, query = "select c from ClientDetailsEntity c where c.clientId = :" + ClientDetailsEntity.PARAM_CLIENT_ID))
/**
 * Create a blank ClientDetailsEntity
 */
@Serializable
open class ClientDetailsEntity(
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null,

    /** Fields from the OAuth2 Dynamic Registration Specification  */
    @SerialName(CLIENT_ID)
    private var clientId: String? = null, // client_id

    @SerialName(CLIENT_SECRET)
    private var clientSecret: String? = null, // client_secret

    @get:Column(name = "redirect_uri")
    @get:CollectionTable(name = "client_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(REDIRECT_URIS)
    open var redirectUris: Set<String> = HashSet(), // redirect_uris

    @get:Column(name = "client_name")
    @get:Basic
    @SerialName(CLIENT_NAME)
    open var clientName: String? = null, // client_name

    @get:Column(name = "client_uri")
    @get:Basic
    @SerialName(CLIENT_URI)
    open var clientUri: String? = null, // client_uri

    @get:Column(name = "logo_uri")
    @get:Basic
    @SerialName(LOGO_URI)
    open var logoUri: String? = null, // logo_uri

    @get:Column(name = "contact")
    @get:CollectionTable(name = "client_contact", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(CONTACTS)
    open var contacts: Set<String>? = null, // contacts

    @get:Column(name = "tos_uri")
    @get:Basic
    @SerialName(TOS_URI)
    open var tosUri: String? = null, // tos_uri

    @get:Column(name = "token_endpoint_auth_method")
    @get:Enumerated(EnumType.STRING)
    @SerialName(TOKEN_ENDPOINT_AUTH_METHOD)
    open var tokenEndpointAuthMethod: AuthMethod? = AuthMethod.SECRET_BASIC, // token_endpoint_auth_method

    @SerialName(SCOPE)
    private var scope: HashSet<String> = HashSet(), // scope

    @get:Column(name = "grant_type")
    @get:CollectionTable(name = "client_grant_type", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(GRANT_TYPES)
    open var grantTypes: MutableSet<String> = HashSet(), // grant_types

    @get:Column(name = "response_type")
    @get:CollectionTable(name = "client_response_type", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(RESPONSE_TYPES)
    open var responseTypes: MutableSet<String> = HashSet(), // response_types

    @get:Column(name = "policy_uri")
    @get:Basic
    @SerialName(POLICY_URI)
    open var policyUri: String? = null,

    @get:Column(name = "jwks_uri")
    @get:Basic
    @SerialName(JWKS_URI)
    open var jwksUri: String? = null, // URI pointer to keys

    @get:Convert(converter = JWKSetStringConverter::class)
    @get:Column(name = "jwks")
    @get:Basic
    @SerialName(JWKS)
    open var jwks: @Serializable(JWSAlgorithmStringConverter::class) JWKSet? = null, // public key stored by value

    @get:Column(name = "software_id")
    @get:Basic
    @SerialName(SOFTWARE_ID)
    open var softwareId: String? = null,

    @get:Column(name = "software_version")
    @get:Basic
    @SerialName(SOFTWARE_VERSION)
    open var softwareVersion: String? = null,

    /** Fields from OIDC Client Registration Specification  */
    @get:Column(name = "application_type")
    @get:Enumerated(EnumType.STRING)
    @SerialName(APPLICATION_TYPE)
    open var applicationType: AppType = AppType.WEB, // application_type

    @get:Column(name = "sector_identifier_uri")
    @get:Basic
    @SerialName(SECTOR_IDENTIFIER_URI)
    open var sectorIdentifierUri: String? = null, // sector_identifier_uri

    @get:Column(name = "subject_type")
    @get:Enumerated(EnumType.STRING)
    @SerialName(SUBJECT_TYPE)
    open var subjectType: SubjectType? = null, // subject_type

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "request_object_signing_alg")
    @get:Basic
    @SerialName(REQUEST_OBJECT_SIGNING_ALG)
    open var requestObjectSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // request_object_signing_alg

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "user_info_signed_response_alg")
    @get:Basic
    @SerialName(USERINFO_SIGNED_RESPONSE_ALG)
    open var userInfoSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // user_info_signed_response_alg

    @get:Convert(converter = JWEAlgorithmStringConverter::class)
    @get:Column(name = "user_info_encrypted_response_alg")
    @get:Basic
    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ALG)
    open var userInfoEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null, // user_info_encrypted_response_alg

    @get:Convert(converter = JWEEncryptionMethodStringConverter::class)
    @get:Column(name = "user_info_encrypted_response_enc")
    @get:Basic
    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ENC)
    open var userInfoEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null, // user_info_encrypted_response_enc

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "id_token_signed_response_alg")
    @get:Basic
    @SerialName(ID_TOKEN_SIGNED_RESPONSE_ALG)
    open var idTokenSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // id_token_signed_response_alg

    @get:Convert(converter = JWEAlgorithmStringConverter::class)
    @get:Column(name = "id_token_encrypted_response_alg")
    @get:Basic
    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ALG)
    open var idTokenEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null, // id_token_encrypted_response_alg

    @get:Convert(converter = JWEEncryptionMethodStringConverter::class)
    @get:Column(name = "id_token_encrypted_response_enc")
    @get:Basic
    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ENC)
    open var idTokenEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null, // id_token_encrypted_response_enc

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "token_endpoint_auth_signing_alg")
    @get:Basic
    @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG)
    open var tokenEndpointAuthSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null, // token_endpoint_auth_signing_alg

    @get:Column(name = "default_max_age")
    @get:Basic
    @SerialName(DEFAULT_MAX_AGE)
    open var defaultMaxAge: Int? = null, // default_max_age

    @get:Column(name = "require_auth_time")
    @get:Basic
    @SerialName(REQUIRE_AUTH_TIME)
    open var requireAuthTime: Boolean? = null, // require_auth_time

    @get:Column(name = "default_acr_value")
    @get:CollectionTable(name = "client_default_acr_value", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(DEFAULT_ACR_VALUES)
    open var defaultACRvalues: Set<String>? = null, // default_acr_values

    @get:Column(name = "initiate_login_uri")
    @get:Basic
    @SerialName(INITIATE_LOGIN_URI)
    var initiateLoginUri: String? = null, // initiate_login_uri

    @get:Column(name = "post_logout_redirect_uri")
    @get:CollectionTable(name = "client_post_logout_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(POST_LOGOUT_REDIRECT_URIS)
    var postLogoutRedirectUris: Set<String>? = null, // post_logout_redirect_uris

    @get:Column(name = "request_uri")
    @get:CollectionTable(name = "client_request_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(REQUEST_URIS)
    var requestUris: Set<String>? = null, // request_uris

    /**
     * Human-readable long description of the client (optional)
     */
    @get:Column(name = "client_description")
    @get:Basic
    @KXS_Transient
    open var clientDescription: String = "", // human-readable description

    @get:Column(name = "reuse_refresh_tokens")
    @get:Basic
    @KXS_Transient
    open var isReuseRefreshToken: Boolean = true, // do we let someone reuse a refresh token?

    @get:Column(name = "dynamically_registered")
    @get:Basic
    @KXS_Transient
    open var isDynamicallyRegistered: Boolean = false, // was this client dynamically registered?

    @get:Column(name = "allow_introspection")
    @get:Basic
    @KXS_Transient
    open var isAllowIntrospection: Boolean = false, // do we let this client call the introspection endpoint?

    @get:Column(name = "id_token_validity_seconds")
    @get:Basic
    @KXS_Transient
    open var idTokenValiditySeconds: Int? = null, //timeout for id tokens

    @get:Column(name = "created_at")
    @get:Temporal(TemporalType.TIMESTAMP)
    @KXS_Transient
    open var createdAt: Date? = null, // time the client was created

    @get:Column(name = "clear_access_tokens_on_refresh")
    @get:Basic
    @KXS_Transient
    open var isClearAccessTokensOnRefresh: Boolean = true, // do we clear access tokens on refresh?

    @get:Column(name = "device_code_validity_seconds")
    @get:Basic
    @KXS_Transient
    open var deviceCodeValiditySeconds: Int? = null, // timeout for device codes

    /** fields for UMA  */
    @get:Column(name = "redirect_uri")
    @get:CollectionTable(name = "client_claims_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @SerialName(CLAIMS_REDIRECT_URIS)
    open var claimsRedirectUris: Set<String>? = null,

    /** Software statement  */
    @get:Convert(converter = JWTStringConverter::class)
    @get:Column(name = "software_statement")
    @get:Basic
    @SerialName(SOFTWARE_STATEMENT)
    open var softwareStatement: @Serializable(JWTStringConverter::class) JWT? = null,

    /** PKCE  */
    @get:Convert(converter = PKCEAlgorithmStringConverter::class)
    @get:Column(name = "code_challenge_method")
    @get:Basic
    @SerialName(CODE_CHALLENGE_METHOD)
    open var codeChallengeMethod: PKCEAlgorithm? = null,
) : ClientDetails {
    /** Fields to support the ClientDetails interface  */
    @KXS_Transient
    private var authorities: Set<GrantedAuthority> = HashSet()

    @KXS_Transient
    private var accessTokenValiditySeconds: Int? = 0 // in seconds

    @KXS_Transient
    private var refreshTokenValiditySeconds: Int? = 0 // in seconds

    @KXS_Transient
    private var resourceIds: Set<String> = HashSet()

    @KXS_Transient
    private val additionalInformation: Map<String, Any> = HashMap()

    @Serializable
    enum class AuthMethod(val value: String) {
        @SerialName("client_secret_post") SECRET_POST("client_secret_post"),
        @SerialName("client_secret_basic") SECRET_BASIC("client_secret_basic"),
        @SerialName("client_secret_jwt") SECRET_JWT("client_secret_jwt"),
        @SerialName("private_key_jwt") PRIVATE_KEY("private_key_jwt"),
        @SerialName("none") NONE("none");

        companion object {
            // map to aid reverse lookup
            private val lookup: Map<String, AuthMethod> by lazy {
                entries.associateBy { it.value }
            }

            @JvmStatic
            fun getByValue(value: String): AuthMethod? {
                return lookup[value]
            }
        }
    }

    @Serializable
    enum class AppType(val value: String) {
        @SerialName("web") WEB("web"),
        @SerialName("native") NATIVE("native");

        companion object {
            // map to aid reverse lookup
            private val lookup: Map<String, AppType> by lazy {
                entries.associateBy { it.value }
            }

            @JvmStatic
            fun getByValue(value: String): AppType? {
                return lookup[value]
            }
        }
    }

    @Serializable
    enum class SubjectType(val value: String) {
        @SerialName("pairwise") PAIRWISE("pairwise"),
        @SerialName("public") PUBLIC("public");

        companion object {
            // map to aid reverse lookup
            private val lookup: Map<String, SubjectType> by lazy {
                entries.associateBy { it.value }
            }

            @JvmStatic
            fun getByValue(value: String): SubjectType? {
                return lookup[value]
            }
        }
    }

    @PrePersist
    @PreUpdate
    protected open fun prePersist() {
        // make sure that ID tokens always time out, default to 5 minutes
        if (idTokenValiditySeconds == null) {
            idTokenValiditySeconds = DEFAULT_ID_TOKEN_VALIDITY_SECONDS
        }
    }

    @get:JPATransient
    val isAllowRefresh: Boolean
        get() {
            return grantTypes.let { "refresh_token" in it }
            // if there are no grants, we can't be refreshing them, can we?
        }


    @JPATransient
    override fun isSecretRequired(): Boolean {
        return tokenEndpointAuthMethod != null &&
            (tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC ||
                    tokenEndpointAuthMethod == AuthMethod.SECRET_POST ||
                    tokenEndpointAuthMethod == AuthMethod.SECRET_JWT)
    }

    /**
     * If the scope list is not null or empty, then this client has been scoped.
     */
    @JPATransient
    override fun isScoped(): Boolean {
        return getScope().isNotEmpty()
    }

    @Basic
    @Column(name = "client_id")
    override fun getClientId(): String? {
        return clientId
    }

    /**
     * @param clientId The OAuth2 client_id, must be unique to this client
     */
    fun setClientId(clientId: String?) {
        this.clientId = clientId
    }

    @Basic
    @Column(name = "client_secret")
    override fun getClientSecret(): String? {
        return clientSecret
    }

    /**
     * @param clientSecret the OAuth2 client_secret (optional)
     */
    fun setClientSecret(clientSecret: String?) {
        this.clientSecret = clientSecret
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @Column(name = "scope")
    override fun getScope(): MutableSet<String> {
        return scope
    }

    /**
     * @param scope the set of scopes allowed to be issued to this client
     */
    fun setScope(scope: Set<String>?) {
        this.scope = scope?.toHashSet() ?: hashSetOf()
    }

    /**
     * passthrough for SECOAUTH api
     */
    @JPATransient
    override fun getAuthorizedGrantTypes(): MutableSet<String> {
        return grantTypes
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_authority", joinColumns = [JoinColumn(name = "owner_id")])
    @Convert(converter = SimpleGrantedAuthorityStringConverter::class)
    @Column(name = "authority")
    override fun getAuthorities(): Set<GrantedAuthority> {
        return authorities
    }

    /**
     * @param authorities the Spring Security authorities this client is given
     */
    fun setAuthorities(authorities: Set<GrantedAuthority>) {
        this.authorities = authorities
    }

    @Basic
    @Column(name = "access_token_validity_seconds")
    override fun getAccessTokenValiditySeconds(): Int? {
        return accessTokenValiditySeconds
    }

    fun setAccessTokenValiditySeconds(accessTokenValiditySeconds: Int?) {
        this.accessTokenValiditySeconds = accessTokenValiditySeconds
    }

    @Basic
    @Column(name = "refresh_token_validity_seconds")
    override fun getRefreshTokenValiditySeconds(): Int? {
        return refreshTokenValiditySeconds
    }

    /**
     * @param refreshTokenTimeout Lifetime of refresh tokens, in seconds (optional - leave null for no timeout)
     */
    fun setRefreshTokenValiditySeconds(refreshTokenValiditySeconds: Int?) {
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds
    }

    /**
     * Pass-through method to fulfill the ClientDetails interface with a bad name
     */
    @JPATransient
    override fun getRegisteredRedirectUri(): Set<String>? {
        return redirectUris
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_resource", joinColumns = [JoinColumn(name = "owner_id")])
    @Column(name = "resource_id")
    override fun getResourceIds(): Set<String> {
        return resourceIds
    }

    fun setResourceIds(resourceIds: Set<String>) {
        this.resourceIds = resourceIds
    }


    /**
     * This library does not make use of this field, so it is not
     * stored using our persistence layer.
     *
     * However, it's somehow required by SECOUATH.
     *
     * @return an empty map
     */
    @JPATransient
    override fun getAdditionalInformation(): Map<String, Any> {
        return this.additionalInformation
    }


    /**
     * Our framework doesn't use this construct, we use WhitelistedSites and ApprovedSites instead.
     */
    override fun isAutoApprove(scope: String): Boolean {
        return false
    }

    companion object {
        const val QUERY_BY_CLIENT_ID: String = "ClientDetailsEntity.getByClientId"
        const val QUERY_ALL: String = "ClientDetailsEntity.findAll"

        const val PARAM_CLIENT_ID: String = "clientId"

        private const val DEFAULT_ID_TOKEN_VALIDITY_SECONDS = 600

        private const val serialVersionUID = -1617727085733786296L
    }
}
