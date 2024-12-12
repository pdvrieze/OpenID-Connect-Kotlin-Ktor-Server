package org.mitre.oauth2.service

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.PKCEAlgorithm
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService
import java.util.*

interface SpringClientDetailsEntityService : /*ClientDetailsEntityService, */ClientDetailsService {

    override fun loadClientByClientId(clientId: String): SpringClientDetailsEntity.OIDClientDetails?

}

class SpringClientDetailsEntity(private val base: OAuthClientDetails.Builder) : OAuthClientDetails {

    constructor(clientDetails: OAuthClientDetails) : this(clientDetails.builder())

    override var clientId: String = base.clientId ?: ""

    override val id: Long
        get() = TODO("not implemented")
    override val clientSecret: String
        get() = TODO("not implemented")
    override val scope: Set<String>
        get() = TODO("not implemented")
    override val authorizedGrantTypes: Set<String>
        get() = TODO("not implemented")
    override val tokenEndpointAuthMethod: OAuthClientDetails.AuthMethod
        get() = TODO("not implemented")
    override val redirectUris: Set<String>
        get() = TODO("not implemented")
    override val clientName: String
        get() = TODO("not implemented")
    override val clientUri: String
        get() = TODO("not implemented")
    override val logoUri: String
        get() = TODO("not implemented")
    override val contacts: Set<String>
        get() = TODO("not implemented")
    override val tosUri: String
        get() = TODO("not implemented")
    override val responseTypes: Set<String>
        get() = TODO("not implemented")
    override val policyUri: String
        get() = TODO("not implemented")
    override val jwksUri: String
        get() = TODO("not implemented")
    override val jwks: JWKSet
        get() = TODO("not implemented")
    override val softwareId: String
        get() = TODO("not implemented")
    override val softwareVersion: String
        get() = TODO("not implemented")
    override val applicationType: OAuthClientDetails.AppType
        get() = TODO("not implemented")
    override val sectorIdentifierUri: String
        get() = TODO("not implemented")
    override val subjectType: OAuthClientDetails.SubjectType
        get() = TODO("not implemented")
    override val requestObjectSigningAlg: JWSAlgorithm
        get() = TODO("not implemented")
    override val userInfoSignedResponseAlg: JWSAlgorithm
        get() = TODO("not implemented")
    override val userInfoEncryptedResponseAlg: JWEAlgorithm
        get() = TODO("not implemented")
    override val userInfoEncryptedResponseEnc: EncryptionMethod
        get() = TODO("not implemented")
    override val idTokenSignedResponseAlg: JWSAlgorithm
        get() = TODO("not implemented")
    override val idTokenEncryptedResponseAlg: JWEAlgorithm
        get() = TODO("not implemented")
    override val idTokenEncryptedResponseEnc: EncryptionMethod
        get() = TODO("not implemented")
    override val tokenEndpointAuthSigningAlg: JWSAlgorithm
        get() = TODO("not implemented")
    override val defaultMaxAge: Long
        get() = TODO("not implemented")
    override val requireAuthTime: Boolean
        get() = TODO("not implemented")
    override val defaultACRvalues: Set<String>
        get() = TODO("not implemented")
    override val initiateLoginUri: String
        get() = TODO("not implemented")
    override val postLogoutRedirectUris: Set<String>
        get() = TODO("not implemented")
    override val requestUris: Set<String>
        get() = TODO("not implemented")
    override val clientDescription: String
        get() = TODO("not implemented")
    override val isReuseRefreshToken: Boolean
        get() = TODO("not implemented")
    override val isDynamicallyRegistered: Boolean
        get() = TODO("not implemented")
    override val isAllowIntrospection: Boolean
        get() = TODO("not implemented")
    override val idTokenValiditySeconds: Int
        get() = TODO("not implemented")
    override val createdAt: Date
        get() = TODO("not implemented")
    override val isClearAccessTokensOnRefresh: Boolean
        get() = TODO("not implemented")
    override val deviceCodeValiditySeconds: Long
        get() = TODO("not implemented")
    override val claimsRedirectUris: Set<String>
        get() = TODO("not implemented")
    override val softwareStatement: JWT
        get() = TODO("not implemented")
    override val codeChallengeMethod: PKCEAlgorithm
        get() = TODO("not implemented")
    override val authorities: Set<org.mitre.oauth2.model.GrantedAuthority>
        get() = TODO("not implemented")
    override val accessTokenValiditySeconds: Int
        get() = TODO("not implemented")
    override val refreshTokenValiditySeconds: Int
        get() = TODO("not implemented")
    override val resourceIds: Set<String>
        get() = TODO("not implemented")
    override val additionalInformation: Map<String, Any>
        get() = TODO("not implemented")

    override fun builder(): OAuthClientDetails.Builder {
        return base
    }

    override fun copy(
        id: Long?,
        clientId: String,
        clientSecret: String?,
        redirectUris: Set<String>,
        clientName: String?,
        clientUri: String?,
        logoUri: String?,
        contacts: Set<String>?,
        tosUri: String?,
        tokenEndpointAuthMethod: OAuthClientDetails.AuthMethod?,
        scope: Set<String>?,
        authorizedGrantTypes: Set<String>,
        responseTypes: Set<String>,
        policyUri: String?,
        jwksUri: String?,
        jwks: JWKSet?,
        softwareId: String?,
        softwareVersion: String?,
        applicationType: OAuthClientDetails.AppType,
        sectorIdentifierUri: String?,
        subjectType: OAuthClientDetails.SubjectType?,
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
        deviceCodeValiditySeconds: Long?,
        claimsRedirectUris: Set<String>?,
        softwareStatement: JWT?,
        codeChallengeMethod: PKCEAlgorithm?,
        accessTokenValiditySeconds: Int?,
        refreshTokenValiditySeconds: Int?,
        authorities: Set<org.mitre.oauth2.model.GrantedAuthority>,
        resourceIds: Set<String>,
        additionalInformation: Map<String, Any>,
    ): ClientDetailsEntity {
        TODO("not implemented")
    }

    val clientDetails: OIDClientDetails = OIDClientDetails()

    inner class OIDClientDetails : ClientDetails {
        val requestObjectSigningAlg: JWSAlgorithm get() = this@SpringClientDetailsEntity.requestObjectSigningAlg

        fun fromSpring(): SpringClientDetailsEntity = this@SpringClientDetailsEntity

        override fun getClientId(): String = this@SpringClientDetailsEntity.clientId

        override fun getResourceIds(): Set<String> = this@SpringClientDetailsEntity.resourceIds

        override fun isSecretRequired(): Boolean = this@SpringClientDetailsEntity.isSecretRequired

        override fun getClientSecret(): String = this@SpringClientDetailsEntity.clientSecret

        override fun isScoped(): Boolean = this@SpringClientDetailsEntity.isScoped

        override fun getScope(): Set<String> = this@SpringClientDetailsEntity.scope

        override fun getAuthorizedGrantTypes(): Set<String> = this@SpringClientDetailsEntity.authorizedGrantTypes

        override fun getRegisteredRedirectUri(): Set<String> = this@SpringClientDetailsEntity.redirectUris

        override fun getAuthorities(): Collection<GrantedAuthority> = this@SpringClientDetailsEntity.authorities.map { SimpleGrantedAuthority(it.authority)}

        override fun getAccessTokenValiditySeconds(): Int = this@SpringClientDetailsEntity.accessTokenValiditySeconds

        override fun getRefreshTokenValiditySeconds(): Int = this@SpringClientDetailsEntity.refreshTokenValiditySeconds

        override fun isAutoApprove(scope: String?): Boolean = false

        override fun getAdditionalInformation(): Map<String, Any> = this@SpringClientDetailsEntity.additionalInformation
    }

}
