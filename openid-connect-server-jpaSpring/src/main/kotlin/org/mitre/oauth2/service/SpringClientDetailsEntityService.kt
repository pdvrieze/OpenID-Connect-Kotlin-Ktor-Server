package org.mitre.oauth2.service

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.ClientDetailsService

interface SpringClientDetailsEntityService : ClientDetailsEntityService, ClientDetailsService {

    override fun loadClientByClientId(clientId: String): SpringClientDetailsEntity?

}

class SpringClientDetailsEntity(base: OAuthClientDetails) : ClientDetailsEntity(
    id = base.id,
    clientId = base.clientId,
    clientSecret = base.clientSecret,
    redirectUris = base.redirectUris,
    clientName = base.clientName,
    clientUri = base.clientUri,
    logoUri = base.logoUri,
    contacts = base.contacts,
    tosUri = base.tosUri,
    tokenEndpointAuthMethod = base.tokenEndpointAuthMethod,
    scope = base.scope,
    authorizedGrantTypes = base.authorizedGrantTypes,
    responseTypes = base.responseTypes.toHashSet(),
    policyUri = base.policyUri,
    jwksUri = base.jwksUri,
    jwks = base.jwks,
    softwareId = base.softwareId,
    softwareVersion = base.softwareVersion,
    applicationType = base.applicationType,
    sectorIdentifierUri = base.sectorIdentifierUri,
    subjectType = base.subjectType,
    requestObjectSigningAlg = base.requestObjectSigningAlg,
    userInfoSignedResponseAlg = base.userInfoSignedResponseAlg,
    userInfoEncryptedResponseAlg = base.userInfoEncryptedResponseAlg,
    userInfoEncryptedResponseEnc = base.userInfoEncryptedResponseEnc,
    idTokenSignedResponseAlg = base.idTokenSignedResponseAlg,
    idTokenEncryptedResponseAlg = base.idTokenEncryptedResponseAlg,
    idTokenEncryptedResponseEnc = base.idTokenEncryptedResponseEnc,
    tokenEndpointAuthSigningAlg = base.tokenEndpointAuthSigningAlg,
    defaultMaxAge = base.defaultMaxAge,
    requireAuthTime = base.requireAuthTime,
    defaultACRvalues = base.defaultACRvalues,
    initiateLoginUri = base.initiateLoginUri,
    postLogoutRedirectUris = base.postLogoutRedirectUris,
    requestUris = base.requestUris,
    clientDescription = base.clientDescription,
    isReuseRefreshToken = base.isReuseRefreshToken,
    isDynamicallyRegistered = base.isDynamicallyRegistered,
    isAllowIntrospection = base.isAllowIntrospection,
    idTokenValiditySeconds = base.idTokenValiditySeconds ?: -1,
    createdAt = base.createdAt,
    isClearAccessTokensOnRefresh = base.isClearAccessTokensOnRefresh,
    deviceCodeValiditySeconds = base.deviceCodeValiditySeconds,
    claimsRedirectUris = base.claimsRedirectUris,
    softwareStatement = base.softwareStatement,
    codeChallengeMethod = base.codeChallengeMethod,
    accessTokenValiditySeconds = base.accessTokenValiditySeconds
), ClientDetails {
    override var clientId: String? = super.clientId

    override fun getResourceIds(): Set<String> = super.resourceIds

    override fun isSecretRequired(): Boolean = super.isSecretRequired

    override fun getClientSecret(): String? = super.clientSecret

    override fun isScoped(): Boolean = super.isScoped

    override fun getScope(): Set<String>? = super.scope

    override fun getAuthorizedGrantTypes(): Set<String> = super.authorizedGrantTypes

    override fun getRegisteredRedirectUri(): Set<String> = super.redirectUris

    override fun getAuthorities(): Collection<GrantedAuthority> = super.authorities.map { SimpleGrantedAuthority(it.authority)}

    override fun getAccessTokenValiditySeconds(): Int? = super.accessTokenValiditySeconds

    override fun getRefreshTokenValiditySeconds(): Int? = super.refreshTokenValiditySeconds

    override fun isAutoApprove(scope: String?): Boolean = false

    override fun getAdditionalInformation(): Map<String, Any> = super.additionalInformation
}
