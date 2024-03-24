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
/**
 *
 */
package org.mitre.oauth2.model

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.convert.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.provider.ClientDetails
import java.util.*
import javax.persistence.*

/**
 * @author jricher
 */
@Entity
@Table(name = "client_details")
@NamedQueries(NamedQuery(name = ClientDetailsEntity.QUERY_ALL, query = "SELECT c FROM ClientDetailsEntity c"), NamedQuery(name = ClientDetailsEntity.QUERY_BY_CLIENT_ID, query = "select c from ClientDetailsEntity c where c.clientId = :" + ClientDetailsEntity.PARAM_CLIENT_ID))
/**
 * Create a blank ClientDetailsEntity
 */
open class ClientDetailsEntity : ClientDetails {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    /** Fields from the OAuth2 Dynamic Registration Specification  */
    private var clientId: String? = null // client_id
    private var clientSecret: String? = null // client_secret

    @get:Column(name = "redirect_uri")
    @get:CollectionTable(name = "client_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var redirectUris: Set<String> = HashSet() // redirect_uris

    @get:Column(name = "client_name")
    @get:Basic
    open var clientName: String? = null // client_name

    @get:Column(name = "client_uri")
    @get:Basic
    open var clientUri: String? = null // client_uri

    @get:Column(name = "logo_uri")
    @get:Basic
    open var logoUri: String? = null // logo_uri

    @get:Column(name = "contact")
    @get:CollectionTable(name = "client_contact", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var contacts: Set<String>? = null // contacts

    @get:Column(name = "tos_uri")
    @get:Basic
    open var tosUri: String? = null // tos_uri

    @get:Column(name = "token_endpoint_auth_method")
    @get:Enumerated(EnumType.STRING)
    open var tokenEndpointAuthMethod: AuthMethod? = AuthMethod.SECRET_BASIC // token_endpoint_auth_method
    private var scope: Set<String> = HashSet() // scope

    @get:Column(name = "grant_type")
    @get:CollectionTable(name = "client_grant_type", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var grantTypes: Set<String> = HashSet() // grant_types

    @get:Column(name = "response_type")
    @get:CollectionTable(name = "client_response_type", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var responseTypes: Set<String> = HashSet() // response_types

    @get:Column(name = "policy_uri")
    @get:Basic
    open var policyUri: String? = null

    @get:Column(name = "jwks_uri")
    @get:Basic
    open var jwksUri: String? = null // URI pointer to keys

    @get:Convert(converter = JWKSetStringConverter::class)
    @get:Column(name = "jwks")
    @get:Basic
    open var jwks: JWKSet? = null // public key stored by value

    @get:Column(name = "software_id")
    @get:Basic
    open var softwareId: String? = null

    @get:Column(name = "software_version")
    @get:Basic
    open var softwareVersion: String? = null

    /** Fields from OIDC Client Registration Specification  */
    @get:Column(name = "application_type")
    @get:Enumerated(EnumType.STRING)
    open var applicationType: AppType? = null // application_type

    @get:Column(name = "sector_identifier_uri")
    @get:Basic
    open var sectorIdentifierUri: String? = null // sector_identifier_uri

    @get:Column(name = "subject_type")
    @get:Enumerated(EnumType.STRING)
    open var subjectType: SubjectType? = null // subject_type

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "request_object_signing_alg")
    @get:Basic
    open var requestObjectSigningAlg: JWSAlgorithm? = null // request_object_signing_alg

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "user_info_signed_response_alg")
    @get:Basic
    open var userInfoSignedResponseAlg: JWSAlgorithm? = null // user_info_signed_response_alg

    @get:Convert(converter = JWEAlgorithmStringConverter::class)
    @get:Column(name = "user_info_encrypted_response_alg")
    @get:Basic
    open var userInfoEncryptedResponseAlg: JWEAlgorithm? = null // user_info_encrypted_response_alg

    @get:Convert(converter = JWEEncryptionMethodStringConverter::class)
    @get:Column(name = "user_info_encrypted_response_enc")
    @get:Basic
    open var userInfoEncryptedResponseEnc: EncryptionMethod? = null // user_info_encrypted_response_enc

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "id_token_signed_response_alg")
    @get:Basic
    open var idTokenSignedResponseAlg: JWSAlgorithm? = null // id_token_signed_response_alg

    @get:Convert(converter = JWEAlgorithmStringConverter::class)
    @get:Column(name = "id_token_encrypted_response_alg")
    @get:Basic
    open var idTokenEncryptedResponseAlg: JWEAlgorithm? = null // id_token_encrypted_response_alg

    @get:Convert(converter = JWEEncryptionMethodStringConverter::class)
    @get:Column(name = "id_token_encrypted_response_enc")
    @get:Basic
    open var idTokenEncryptedResponseEnc: EncryptionMethod? = null // id_token_encrypted_response_enc

    @get:Convert(converter = JWSAlgorithmStringConverter::class)
    @get:Column(name = "token_endpoint_auth_signing_alg")
    @get:Basic
    open var tokenEndpointAuthSigningAlg: JWSAlgorithm? = null // token_endpoint_auth_signing_alg

    @get:Column(name = "default_max_age")
    @get:Basic
    open var defaultMaxAge: Int? = null // default_max_age

    @get:Column(name = "require_auth_time")
    @get:Basic
    open var requireAuthTime: Boolean? = null // require_auth_time
    /**
     * @return the defaultACRvalues
     */
    /**
     * @param defaultACRvalues the defaultACRvalues to set
     */
    @get:Column(name = "default_acr_value")
    @get:CollectionTable(name = "client_default_acr_value", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var defaultACRvalues: Set<String>? = null // default_acr_values

    @get:Column(name = "initiate_login_uri")
    @get:Basic
    var initiateLoginUri: String? = null // initiate_login_uri

    @get:Column(name = "post_logout_redirect_uri")
    @get:CollectionTable(name = "client_post_logout_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var postLogoutRedirectUris: Set<String>? = null // post_logout_redirect_uris

    @get:Column(name = "request_uri")
    @get:CollectionTable(name = "client_request_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var requestUris: Set<String>? = null // request_uris

    /** Fields to support the ClientDetails interface  */
    private var authorities: Set<GrantedAuthority> = HashSet()
    private var accessTokenValiditySeconds: Int? = 0 // in seconds
    private var refreshTokenValiditySeconds: Int? = 0 // in seconds
    private var resourceIds: Set<String> = HashSet()
    private val additionalInformation: Map<String, Any> = HashMap()

    /**
     * Human-readable long description of the client (optional)
     */
    @get:Column(name = "client_description")
    @get:Basic
    open var clientDescription: String = "" // human-readable description

    @get:Column(name = "reuse_refresh_tokens")
    @get:Basic
    open var isReuseRefreshToken: Boolean = true // do we let someone reuse a refresh token?

    @get:Column(name = "dynamically_registered")
    @get:Basic
    open var isDynamicallyRegistered: Boolean = false // was this client dynamically registered?

    @get:Column(name = "allow_introspection")
    @get:Basic
    open var isAllowIntrospection: Boolean = false // do we let this client call the introspection endpoint?

    @get:Column(name = "id_token_validity_seconds")
    @get:Basic
    open var idTokenValiditySeconds: Int? = null //timeout for id tokens

    @get:Column(name = "created_at")
    @get:Temporal(TemporalType.TIMESTAMP)
    open var createdAt: Date? = null // time the client was created

    @get:Column(name = "clear_access_tokens_on_refresh")
    @get:Basic
    open var isClearAccessTokensOnRefresh: Boolean = true // do we clear access tokens on refresh?

    @get:Column(name = "device_code_validity_seconds")
    @get:Basic
    open var deviceCodeValiditySeconds: Int? = null // timeout for device codes

    /** fields for UMA  */
    @get:Column(name = "redirect_uri")
    @get:CollectionTable(name = "client_claims_redirect_uri", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    open var claimsRedirectUris: Set<String>? = null

    /** Software statement  */
    @get:Convert(converter = JWTStringConverter::class)
    @get:Column(name = "software_statement")
    @get:Basic
    open var softwareStatement: JWT? = null

    /** PKCE  */
    @get:Convert(converter = PKCEAlgorithmStringConverter::class)
    @get:Column(name = "code_challenge_method")
    @get:Basic
    open var codeChallengeMethod: PKCEAlgorithm? = null

    enum class AuthMethod(val value: String) {
        SECRET_POST("client_secret_post"),
        SECRET_BASIC("client_secret_basic"),
        SECRET_JWT("client_secret_jwt"),
        PRIVATE_KEY("private_key_jwt"),
        NONE("none");

        companion object {
            // map to aid reverse lookup
            private val lookup: MutableMap<String, AuthMethod> = HashMap()

            init {
                for (a in entries) {
                    lookup[a.value] = a
                }
            }

            @JvmStatic
            fun getByValue(value: String): AuthMethod? {
                return lookup[value]
            }
        }
    }

    enum class AppType(val value: String) {
        WEB("web"), NATIVE("native");

        companion object {
            // map to aid reverse lookup
            private val lookup: MutableMap<String, AppType> = HashMap()

            init {
                for (a in entries) {
                    lookup[a.value] = a
                }
            }

            @JvmStatic
            fun getByValue(value: String): AppType? {
                return lookup[value]
            }
        }
    }

    enum class SubjectType(val value: String) {
        PAIRWISE("pairwise"), PUBLIC("public");

        companion object {
            // map to aid reverse lookup
            private val lookup: MutableMap<String, SubjectType> = HashMap()

            init {
                for (u in entries) {
                    lookup[u.value] = u
                }
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

    @get:Transient
    val isAllowRefresh: Boolean
        /**
         * @return the allowRefresh
         */
        get() = if (grantTypes != null) {
            authorizedGrantTypes.contains("refresh_token")
        } else {
            false // if there are no grants, we can't be refreshing them, can we?
        }


    /**
     *
     */
    @Transient
    override fun isSecretRequired(): Boolean {
        return if (tokenEndpointAuthMethod != null &&
            (tokenEndpointAuthMethod == AuthMethod.SECRET_BASIC || tokenEndpointAuthMethod == AuthMethod.SECRET_POST || tokenEndpointAuthMethod == AuthMethod.SECRET_JWT)
        ) {
            true
        } else {
            false
        }
    }

    /**
     * If the scope list is not null or empty, then this client has been scoped.
     */
    @Transient
    override fun isScoped(): Boolean {
        return getScope() != null && !getScope().isEmpty()
    }

    /**
     * @return the clientId
     */
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

    /**
     * @return the clientSecret
     */
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

    /**
     * @return the scope
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @Column(name = "scope")
    override fun getScope(): Set<String> {
        return scope
    }

    /**
     * @param scope the set of scopes allowed to be issued to this client
     */
    fun setScope(scope: Set<String>) {
        this.scope = scope
    }

    /**
     * passthrough for SECOAUTH api
     */
    @Transient
    override fun getAuthorizedGrantTypes(): Set<String> {
        return grantTypes
    }

    /**
     * @return the authorities
     */
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

    /**
     * @param accessTokenTimeout the accessTokenTimeout to set
     */
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
    @Transient
    override fun getRegisteredRedirectUri(): Set<String> {
        return redirectUris
    }

    /**
     * @return the resourceIds
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_resource", joinColumns = [JoinColumn(name = "owner_id")])
    @Column(name = "resource_id")
    override fun getResourceIds(): Set<String> {
        return resourceIds
    }

    /**
     * @param resourceIds the resourceIds to set
     */
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
    @Transient
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
