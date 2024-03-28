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

import com.google.gson.JsonObject
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.springframework.security.core.GrantedAuthority
import java.util.*

/**
 * @author jricher
 */
class RegisteredClient @JvmOverloads constructor(
    var client: ClientDetailsEntity = ClientDetailsEntity(),// these fields are needed in addition to the ones in ClientDetailsEntity
    var registrationAccessToken: String? = null, var registrationClientUri: String? = null
) {
    var clientSecretExpiresAt: Date? = null
    var clientIdIssuedAt: Date? = null
    var source: JsonObject? = null

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

    var scope: Set<String>
        get() = client.scope
        set(scope) {
            client.setScope(scope)
        }

    var grantTypes: Set<String>
        get() = client.grantTypes
        set(grantTypes) {
            client.grantTypes = grantTypes
        }

    val authorizedGrantTypes: Set<String>
        get() = client.authorizedGrantTypes

    var authorities: Set<GrantedAuthority>
        get() = client.authorities
        set(authorities) {
            client.setAuthorities(authorities)
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
            client.setResourceIds(resourceIds)
        }
    
    val additionalInformation: Map<String, Any>
        get() = client.additionalInformation
    
    var applicationType: AppType?
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
        set(responseTypes) { client.responseTypes = responseTypes }

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
        get() = client.createdAt
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
}
