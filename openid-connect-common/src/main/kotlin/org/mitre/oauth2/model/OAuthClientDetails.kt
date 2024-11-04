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
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_NAME
import org.mitre.oauth2.model.RegisteredClientFields.CLIENT_URI
import org.mitre.oauth2.model.RegisteredClientFields.CODE_CHALLENGE_METHOD
import org.mitre.oauth2.model.RegisteredClientFields.CONTACTS
import org.mitre.oauth2.model.RegisteredClientFields.DEFAULT_ACR_VALUES
import org.mitre.oauth2.model.RegisteredClientFields.DEFAULT_MAX_AGE
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
import org.mitre.oauth2.model.RegisteredClientFields.SECTOR_IDENTIFIER_URI
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_ID
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_STATEMENT
import org.mitre.oauth2.model.RegisteredClientFields.SOFTWARE_VERSION
import org.mitre.oauth2.model.RegisteredClientFields.SUBJECT_TYPE
import org.mitre.oauth2.model.RegisteredClientFields.TOKEN_ENDPOINT_AUTH_SIGNING_ALG
import org.mitre.oauth2.model.RegisteredClientFields.TOS_URI
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ALG
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_ENCRYPTED_RESPONSE_ENC
import org.mitre.oauth2.model.RegisteredClientFields.USERINFO_SIGNED_RESPONSE_ALG
import org.mitre.oauth2.model.convert.JWTStringConverter
import java.util.*
import kotlinx.serialization.Transient as KXS_Transient


interface OAuthClientDetails {
    val id: Long?

    val clientId: String

    val clientSecret: String?

    val scope: Set<String>?

    @Deprecated("Use authorizedGrantTypes", ReplaceWith("authorizedGrantTypes"))
    val grantTypes: Set<String> get() = authorizedGrantTypes

    val authorizedGrantTypes: Set<String>

    val tokenEndpointAuthMethod: AuthMethod?

    val isAllowRefresh: Boolean
        get() = "refresh_token" in authorizedGrantTypes

    @SerialName(REDIRECT_URIS)
    val redirectUris: Set<String>

    @SerialName(CLIENT_NAME)
    val clientName: String?

    @SerialName(CLIENT_URI)
    val clientUri: String?

    @SerialName(LOGO_URI)
    val logoUri: String?

    @SerialName(CONTACTS)
    val contacts: Set<String>?

    @SerialName(TOS_URI)
    val tosUri: String?

    @SerialName(RESPONSE_TYPES)
    val responseTypes: Set<String>

    @SerialName(POLICY_URI)
    val policyUri: String?

    @SerialName(JWKS_URI)
    val jwksUri: String?

    @SerialName(JWKS)
    val jwks: JWKSet?

    @SerialName(SOFTWARE_ID)
    val softwareId: String?

    @SerialName(SOFTWARE_VERSION)
    val softwareVersion: String?

    /** Fields from OIDC Client Registration Specification  */
    @SerialName(APPLICATION_TYPE)
    val applicationType: AppType

    @SerialName(SECTOR_IDENTIFIER_URI)
    val sectorIdentifierUri: String?

    @SerialName(SUBJECT_TYPE)
    val subjectType: SubjectType?

    @SerialName(REQUEST_OBJECT_SIGNING_ALG)
    val requestObjectSigningAlg: JWSAlgorithm?

    @SerialName(USERINFO_SIGNED_RESPONSE_ALG)
    val userInfoSignedResponseAlg: JWSAlgorithm?

    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ALG)
    val userInfoEncryptedResponseAlg: JWEAlgorithm?

    @SerialName(USERINFO_ENCRYPTED_RESPONSE_ENC)
    val userInfoEncryptedResponseEnc: EncryptionMethod?

    @SerialName(ID_TOKEN_SIGNED_RESPONSE_ALG)
    val idTokenSignedResponseAlg: JWSAlgorithm?

    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ALG)
    val idTokenEncryptedResponseAlg: JWEAlgorithm?

    @SerialName(ID_TOKEN_ENCRYPTED_RESPONSE_ENC)
    val idTokenEncryptedResponseEnc: EncryptionMethod?

    @SerialName(TOKEN_ENDPOINT_AUTH_SIGNING_ALG)
    val tokenEndpointAuthSigningAlg: JWSAlgorithm?

    @SerialName(DEFAULT_MAX_AGE)
    val defaultMaxAge: Long?

    @SerialName(REQUIRE_AUTH_TIME)
    val requireAuthTime: Boolean?

    @SerialName(DEFAULT_ACR_VALUES)
    val defaultACRvalues: Set<String>?

    @SerialName(INITIATE_LOGIN_URI)
    val initiateLoginUri: String?

    @SerialName(POST_LOGOUT_REDIRECT_URIS)
    val postLogoutRedirectUris: Set<String>?

    @SerialName(REQUEST_URIS)
    val requestUris: Set<String>?

    /**
     * Human-readable long description of the client (optional)
     */
    @KXS_Transient
    val clientDescription: String

    @KXS_Transient
    val isReuseRefreshToken: Boolean

    @KXS_Transient
    val isDynamicallyRegistered: Boolean

    @KXS_Transient
    val isAllowIntrospection: Boolean

    @KXS_Transient
    val idTokenValiditySeconds: Int?

    @KXS_Transient
    val createdAt: Date?

    @KXS_Transient
    val isClearAccessTokensOnRefresh: Boolean

    @KXS_Transient
    val deviceCodeValiditySeconds: Int?

    /** fields for UMA  */
    @SerialName(CLAIMS_REDIRECT_URIS)
    val claimsRedirectUris: Set<String>?

    /** Software statement  */
    @SerialName(SOFTWARE_STATEMENT)
    val softwareStatement: @Serializable(JWTStringConverter::class) JWT?

    /** PKCE  */
    @SerialName(CODE_CHALLENGE_METHOD)
    val codeChallengeMethod: PKCEAlgorithm?
    // if there are no grants, we can't be refreshing them, can we?

    val isSecretRequired: Boolean
        get() = tokenEndpointAuthMethod in SECRET_REQUIRING_METHODS

    val isScoped: Boolean get() = ! scope.isNullOrEmpty()

    val authorities: Set<GrantedAuthority>

    val accessTokenValiditySeconds: Int?

    val refreshTokenValiditySeconds: Int?

    fun withId(id: Long): OAuthClientDetails = copy(id = id)

    /**
     * Pass-through method to fulfill the ClientDetails interface with a bad name
     */
    @Deprecated("Not needed", ReplaceWith("redirectUris"))
    val registeredRedirectUri: Set<String>? get() = redirectUris

    val resourceIds: Set<String>

    val additionalInformation: Map<String, Any>

    fun builder(): Builder

    fun copy(
        id: Long? = this.id,
        clientId: String = this.clientId,
        clientSecret: String? = this.clientSecret,
        redirectUris: Set<String> = this.redirectUris,
        clientName: String? = this.clientName,
        clientUri: String? = this.clientUri,
        logoUri: String? = this.logoUri,
        contacts: Set<String>? = this.contacts,
        tosUri: String? = this.tosUri,
        tokenEndpointAuthMethod: AuthMethod? = this.tokenEndpointAuthMethod,
        scope: Set<String>? = this.scope,
        authorizedGrantTypes: Set<String> = this.authorizedGrantTypes,
        responseTypes: Set<String> = this.responseTypes,
        policyUri: String? = this.policyUri,
        jwksUri: String? = this.jwksUri,
        jwks: JWKSet? = this.jwks,
        softwareId: String? = this.softwareId,
        softwareVersion: String? = this.softwareVersion,
        applicationType: AppType = this.applicationType,
        sectorIdentifierUri: String? = this.sectorIdentifierUri,
        subjectType: SubjectType? = this.subjectType,
        requestObjectSigningAlg: JWSAlgorithm? = this.requestObjectSigningAlg,
        userInfoSignedResponseAlg: JWSAlgorithm? = this.userInfoSignedResponseAlg,
        userInfoEncryptedResponseAlg: JWEAlgorithm? = this.userInfoEncryptedResponseAlg,
        userInfoEncryptedResponseEnc: EncryptionMethod? = this.userInfoEncryptedResponseEnc,
        idTokenSignedResponseAlg: JWSAlgorithm? = this.idTokenSignedResponseAlg,
        idTokenEncryptedResponseAlg: JWEAlgorithm? = this.idTokenEncryptedResponseAlg,
        idTokenEncryptedResponseEnc: EncryptionMethod? = this.idTokenEncryptedResponseEnc,
        tokenEndpointAuthSigningAlg: JWSAlgorithm? = this.tokenEndpointAuthSigningAlg,
        defaultMaxAge: Long? = this.defaultMaxAge,
        requireAuthTime: Boolean? = this.requireAuthTime,
        defaultACRvalues: Set<String>? = this.defaultACRvalues,
        initiateLoginUri: String? = this.initiateLoginUri,
        postLogoutRedirectUris: Set<String>? = this.postLogoutRedirectUris,
        requestUris: Set<String>? = this.requestUris,
        clientDescription: String = this.clientDescription,
        isReuseRefreshToken: Boolean = this.isReuseRefreshToken,
        isDynamicallyRegistered: Boolean = this.isDynamicallyRegistered,
        isAllowIntrospection: Boolean = this.isAllowIntrospection,
        idTokenValiditySeconds: Int? = this.idTokenValiditySeconds,
        createdAt: Date? = this.createdAt,
        isClearAccessTokensOnRefresh: Boolean = this.isClearAccessTokensOnRefresh,
        deviceCodeValiditySeconds: Int? = this.deviceCodeValiditySeconds,
        claimsRedirectUris: Set<String>? = this.claimsRedirectUris,
        softwareStatement: JWT? = this.softwareStatement,
        codeChallengeMethod: PKCEAlgorithm? = this.codeChallengeMethod,
        accessTokenValiditySeconds: Int? = this.accessTokenValiditySeconds,
        refreshTokenValiditySeconds: Int? = this.refreshTokenValiditySeconds,
        authorities: Set<GrantedAuthority> = this.authorities,
        resourceIds: Set<String> = this.resourceIds,
        additionalInformation: Map<String, Any> = this.additionalInformation,
    ): ClientDetailsEntity

    companion object {
        private val SECRET_REQUIRING_METHODS =
            arrayOf(AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST, AuthMethod.SECRET_JWT)
    }

    interface Builder {
        var id: Long?
        var clientId: String?
        var clientSecret: String?
        var scope: MutableSet<String>?
        var authorizedGrantTypes: MutableSet<String>
        var tokenEndpointAuthMethod: AuthMethod?
        var redirectUris: MutableSet<String>
        var clientName: String?
        var clientUri: String?
        var logoUri: String?
        var contacts: MutableSet<String>?
        var tosUri: String?
        var responseTypes: MutableSet<String>
        var policyUri: String?
        var jwksUri: String?
        var jwks: JWKSet?
        var softwareId: String?
        var softwareVersion: String?
        var applicationType: AppType
        var sectorIdentifierUri: String?
        var subjectType: SubjectType?
        var requestObjectSigningAlg: JWSAlgorithm?
        var userInfoSignedResponseAlg: JWSAlgorithm?
        var userInfoEncryptedResponseAlg: JWEAlgorithm?
        var userInfoEncryptedResponseEnc: EncryptionMethod?
        var idTokenSignedResponseAlg: JWSAlgorithm?
        var idTokenEncryptedResponseAlg: JWEAlgorithm?
        var idTokenEncryptedResponseEnc: EncryptionMethod?
        var tokenEndpointAuthSigningAlg: JWSAlgorithm?
        var defaultMaxAge: Long?
        var requireAuthTime: Boolean?
        var defaultACRvalues: MutableSet<String>?
        var initiateLoginUri: String?
        var postLogoutRedirectUris: MutableSet<String>?
        var requestUris: MutableSet<String>?
        var clientDescription: String
        var isReuseRefreshToken: Boolean
        var isDynamicallyRegistered: Boolean
        var isAllowIntrospection: Boolean
        var idTokenValiditySeconds: Int?
        var createdAt: Date?
        var isClearAccessTokensOnRefresh: Boolean
        var deviceCodeValiditySeconds: Int?
        var claimsRedirectUris: MutableSet<String>?
        var softwareStatement: JWT?
        var codeChallengeMethod: PKCEAlgorithm?

        fun build(): OAuthClientDetails
    }


    @Serializable
    enum class AuthMethod(val value: String) {
        @SerialName("client_secret_post")
        SECRET_POST("client_secret_post"),
        @SerialName("client_secret_basic")
        SECRET_BASIC("client_secret_basic"),
        @SerialName("client_secret_jwt")
        SECRET_JWT("client_secret_jwt"),
        @SerialName("private_key_jwt")
        PRIVATE_KEY("private_key_jwt"),
        @SerialName("none")
        NONE("none");

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
        @SerialName("web")
        WEB("web"),
        @SerialName("native")
        NATIVE("native");

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
        @SerialName("pairwise")
        PAIRWISE("pairwise"),
        @SerialName("public")
        PUBLIC("public");

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

}


@Deprecated("Use property directly")
fun ClientDetailsEntity.Builder.setRefreshTokenValiditySeconds(secs: Int) {
    refreshTokenValiditySeconds = secs
}

@Deprecated("Use property directly")
fun ClientDetailsEntity.Builder.setAccessTokenValiditySeconds(secs: Int) {
    accessTokenValiditySeconds = secs
}

@Deprecated("Use property directly", ReplaceWith("this.scope = newScope?.toHashSet() ?: hashSetOf()"))
fun OAuthClientDetails.Builder.setScope(newScope: Set<String>?) {
    this.scope  = newScope?.toHashSet() ?: hashSetOf()
}

@Deprecated("Use property directly")
fun OAuthClientDetails.Builder.setClientSecret(clientSecret: String?) {
    this.clientSecret = clientSecret
}

