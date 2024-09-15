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
package org.mitre.openid.connect.service

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import kotlinx.serialization.ContextualSerializer
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.JWEAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWEEncryptionMethodStringConverter
import org.mitre.oauth2.model.convert.JWKSetStringConverter
import org.mitre.oauth2.model.convert.JWSAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.model.convert.ISODate
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.util.getLogger
import java.io.IOException
import java.text.ParseException
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.*

/**
 * @author jricher
 * @author arielak
 */
interface MITREidDataService {
    /**
     * Write out the current server state as String.
     *
     * @throws IOException
     */
    fun exportData(): String

    /**
     * Read in the current server state from the pre-parsed configuration data
     */
    fun importData(config: ExtendedConfiguration)

    /**
     * Read in the state from a string
     */
    fun importData(configJson: String)

    /**
     * Return true if the this data service supports the given version. This is called before
     * handing the service the reader through its importData function.
     *
     */
    fun supportsVersion(version: String?): Boolean


    fun DataServiceContext.importData(conf: ExtendedConfiguration) {
        for (client in conf.clients) importClient(this, client)
        logger.info("Done reading clients")

        for (delegate in conf.grants) importGrant(this, delegate)
        logger.info("Done reading grants")

        for (wlSite in conf.whitelistedSites) importWhitelistedSite(this, wlSite)
        logger.info("Done reading whitelisted sites")

        for (blSite in conf.blacklistedSites) importBlacklistedSite(this, blSite)
        logger.info("Done reading blacklisted sites")

        for (ahe in conf.authenticationHolders) importAuthenticationHolder(this, ahe)
        logger.info("Done reading authentication holders")

        for (delegate in conf.refreshTokens) importRefreshToken(this, delegate)
        logger.info("Done reading refresh tokens")

        for (delegate in conf.accessTokens) importAccessToken(this, delegate)
        logger.info("Done reading access tokens")

        for (scope in conf.systemScopes) importSystemScope(this, scope)
        logger.info("Done reading system scopes")

        // TODO readExtensions(conf)
        fixObjectReferences(this)
        fixExtensionObjectReferences(this)


        maps.clearAll()

        /*
    maps.clearAll()
*/
    }

    fun importClient(context: DataServiceContext, client: ClientDetailsConfiguration) {
        context.clientRepository.saveClient(client.toClientDetailsEntity())
    }

    fun importGrant(context: DataServiceContext, delegate: ApprovedSite.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId

            if (delegate.whitelistedSiteId != null) {
                logger.debug("Ignoring whitelisted site marker on approved site.")
            }

            val tokenIds: Set<Long> = delegate.approvedAccessTokens

            val site = ApprovedSite(
                accessDate = delegate.accessDate,
                clientId = delegate.clientId,
                creationDate = delegate.creationDate,
                timeoutDate = delegate.timeoutDate,
                userId = delegate.userId,
                allowedScopes = delegate.allowedScopes ?: emptySet(),
            )

            val newId = approvedSiteRepository.save(site).id!!
            maps.grantOldToNewIdMap[currentId] = newId

            if (!tokenIds.isNullOrEmpty()) {
                maps.grantToAccessTokensRefs[currentId] = tokenIds
            }
            logger.debug("Read grant {}", currentId)
        }
    }

    fun importWhitelistedSite(context: DataServiceContext, wlSite: WhitelistedSite) {
        with(context) {
            val currentId: Long = wlSite.id!!
            wlSite.id = null // reset to null

            requireNotNull(currentId)
            val newId = wlSiteRepository.save(wlSite).id!!
            maps.whitelistedSiteOldToNewIdMap[currentId] = newId
        }
    }

    fun importBlacklistedSite(context: DataServiceContext, blSite: BlacklistedSite) {
        blSite.id = null // ignore ID
        context.blSiteRepository.save(blSite)
    }

    fun importAuthenticationHolder(context: DataServiceContext, ahe: AuthenticationHolderEntity) {
        with(context) {
            val currentId: Long = requireNotNull(ahe.id) { "Missing id for authentication holder" }
            ahe.id = null

            val newId = authHolderRepository.save(ahe).id!!
            maps.authHolderOldToNewIdMap[currentId] = newId
            logger.debug("Read authentication holder {}", currentId)
        }
    }

    fun importAccessToken(context: DataServiceContext, delegate: OAuth2AccessTokenEntity.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId
            val clientId: String = delegate.clientId
            val authHolderId: Long = delegate.authenticationHolderId
            val refreshTokenId: Long? = delegate.refreshTokenId

            val authHolder = authHolderRepository.getById(authHolderId) ?: error("Missing authHolder with id $authHolderId")
            val refreshToken = refreshTokenId?.let { tokenRepository.getRefreshTokenById(it) }

            val token = OAuth2AccessTokenEntity(
                id = null,
                expiration = delegate.expiration!!,
                jwt = delegate.value ?: error("Missing token in auth2 access token entity"),
                client = null,
                authenticationHolder = authHolder,
                refreshToken = refreshToken,
                scope = delegate.scope,
                tokenType = delegate.tokenType
            )

            val newId = tokenRepository.saveAccessToken(token).id!!

            maps.accessTokenToClientRefs[currentId] = clientId
            maps.accessTokenToAuthHolderRefs[currentId] = authHolderId
            if (refreshTokenId != null) {
                maps.accessTokenToRefreshTokenRefs[currentId] = refreshTokenId
            }
            maps.accessTokenOldToNewIdMap[currentId] = newId
            logger.debug("Read access token {}", currentId)
        }
    }

    fun importRefreshToken(context: DataServiceContext, delegate: OAuth2RefreshTokenEntity.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId
            val clientId: String = delegate.clientId
            val authHolderId: Long = delegate.authenticationHolderId

            val token = OAuth2RefreshTokenEntity(
                authenticationHolder = DUMMY_AUTH_HOLDER, // dummy value
                expiration = delegate.expiration,
                jwt = delegate.value ?: error("Missing jwt token")
            )

            val newId = tokenRepository.saveRefreshToken(token).id!!

            maps.refreshTokenToClientRefs[currentId] = clientId
            maps.refreshTokenToAuthHolderRefs[currentId] = authHolderId
            maps.refreshTokenOldToNewIdMap[currentId] = newId
            logger.debug("Read refresh token {}", currentId)
        }
    }

    fun importSystemScope(context: DataServiceContext, scope: SystemScope) {
        context.sysScopeRepository.save(scope)
    }

    fun fixExtensionObjectReferences(context: DataServiceContext) {
        for (extension in context.extensions) {
            if (extension.supportsVersion(context.version)) {
                extension.fixExtensionObjectReferences(context.maps)
                break
            }
        }

    }

    fun fixObjectReferences(context: DataServiceContext) {
        with(context) {
            for ((oldRefreshTokenId, clientRef) in maps.refreshTokenToClientRefs) {
                val client = clientRepository.getClientByClientId(clientRef)
                val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
                val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
                refreshToken.client = client?.let(ClientDetailsEntity::from)
                tokenRepository.saveRefreshToken(refreshToken)
            }

            for ((oldRefreshTokenId, oldAuthHolderId) in maps.refreshTokenToAuthHolderRefs) {
                val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId]!!
                val authHolder = authHolderRepository.getById(newAuthHolderId)!!
                val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
                val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
                refreshToken.authenticationHolder = authHolder
                tokenRepository.saveRefreshToken(refreshToken)
            }

            for ((oldAccessTokenId, clientRef) in maps.accessTokenToClientRefs) {
                val client = clientRepository.getClientByClientId(clientRef)
                val newAccessTokenId = maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
                val accessToken = tokenRepository.getAccessTokenById(newAccessTokenId)!!
                accessToken.client = client?.let(ClientDetailsEntity::from)
                tokenRepository.saveAccessToken(accessToken)
            }
            for ((oldAccessTokenId, oldAuthHolderId) in maps.accessTokenToAuthHolderRefs) {
                val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId]!!
                val authHolder = authHolderRepository.getById(newAuthHolderId)!!
                val newAccessTokenId = maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
                val accessToken = tokenRepository.getAccessTokenById(newAccessTokenId)!!
                accessToken.authenticationHolder = authHolder
                tokenRepository.saveAccessToken(accessToken)
            }
            maps.accessTokenToAuthHolderRefs.clear()

            for ((oldAccessTokenId, oldRefreshTokenId) in maps.accessTokenToRefreshTokenRefs) {
                val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
                val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)

                val newAccessTokenId = maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
                val accessToken = tokenRepository.getAccessTokenById(newAccessTokenId)?: error("Missing access token $newAccessTokenId")
//                refreshToken?.let { accessToken.refreshToken = it }
                val newAccessToken = accessToken.copy(refreshToken = refreshToken)
                tokenRepository.saveAccessToken(accessToken)
            }

            for ((oldGrantId, oldAccessTokenIds) in maps.grantToAccessTokensRefs) {
                val newGrantId = maps.grantOldToNewIdMap[oldGrantId]!!
                val site = approvedSiteRepository.getById(newGrantId)!!

                for (oldTokenId in oldAccessTokenIds) {
                    val newTokenId = checkNotNull(maps.accessTokenOldToNewIdMap[oldTokenId]) {
                        "missing map for old access token $oldTokenId"
                    }
                    val token = tokenRepository.getAccessTokenById(newTokenId)!!
                    token.approvedSite = site
                    tokenRepository.saveAccessToken(token)
                }

                approvedSiteRepository.save(site)
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    class ClientDetailsConfiguration(
        @EncodeDefault @SerialName("clientId") val clientId: String,
        @EncodeDefault @SerialName("resourceIds") val resourceIds: Set<String>? = null,
        @EncodeDefault @SerialName("secret") val secret: String? = null,
        @EncodeDefault @SerialName("scope") val scope: Set<String>? = null,
        @EncodeDefault @SerialName("authorities") val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority> = emptySet(),
        @EncodeDefault @SerialName("accessTokenValiditySeconds") val accessTokenValiditySeconds: Int? = null,
        @EncodeDefault @SerialName("refreshTokenValiditySeconds") val refreshTokenValiditySeconds: Int? = null,
        @EncodeDefault @SerialName("idTokenValiditySeconds") val idTokenValiditySeconds: Int? = null,
        @EncodeDefault @SerialName("deviceTokenValiditySeconds") val deviceCodeValiditySeconds: Int? = null,
        @EncodeDefault @SerialName("redirectUris") val redirectUris: Set<String> = hashSetOf(),
        @EncodeDefault @SerialName("claimsRedirectUris") var claimsRedirectUris: Set<String>? = null,
        @EncodeDefault @SerialName("name") val clientName: String? = null,
        @EncodeDefault @SerialName("uri") val clientUri: String? = null,
        @EncodeDefault @SerialName("logoUri") val logoUri: String? = null,
        @EncodeDefault @SerialName("contacts") val contacts: Set<String>? = null,
        @EncodeDefault @SerialName("tosUri") val tosUri: String? = null,
        @EncodeDefault @SerialName("tokenEndpointAuthMethod") val tokenEndpointAuthMethod: OAuthClientDetails.AuthMethod = OAuthClientDetails.AuthMethod.SECRET_BASIC,
        @EncodeDefault @SerialName("grantTypes") val grantTypes: Set<String> = hashSetOf(),
        @EncodeDefault @SerialName("responseTypes") val responseTypes: Set<String> = hashSetOf(),
        @EncodeDefault @SerialName("policyUri") val policyUri: String? = null,
        @EncodeDefault @SerialName("applicationType") val applicationType: OAuthClientDetails.AppType = OAuthClientDetails.AppType.WEB,
        @EncodeDefault @SerialName("sectorIdentifierUri") val sectorIdentifierUri: String? = null,
        @EncodeDefault @SerialName("subjectType") val subjectType: OAuthClientDetails.SubjectType? = null,
        @EncodeDefault @SerialName("jwks_uri") val jwks_uri: String? = null,
        @EncodeDefault @SerialName("jwks") var jwks: @Serializable(JWKSetStringConverter::class) JWKSet? = null,
        @EncodeDefault @SerialName("requestObjectSigningAlg") val requestObjectSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @EncodeDefault @SerialName("userInfoEncryptedResponseAlg") val userInfoEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @EncodeDefault @SerialName("userInfoEncryptedResponseEnc") val userInfoEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @EncodeDefault @SerialName("userInfoSignedResponseAlg") val userInfoSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @EncodeDefault @SerialName("idTokenSignedResonseAlg") val idTokenSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @EncodeDefault @SerialName("idTokenEncryptedResponseAlg") val idTokenEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @EncodeDefault @SerialName("idTokenEncryptedResponseEnc") val idTokenEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @EncodeDefault @SerialName("tokenEndpointAuthSigningAlg") val tokenEndpointAuthSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @EncodeDefault @SerialName("defaultMaxAge") val defaultMaxAge: Long? = null,
        @SerialName("requireAuthTime")
        val requireAuthTime: Boolean? = null,
        @EncodeDefault @SerialName("defaultACRValues") val defaultACRValues: Set<String>? = null,
        @EncodeDefault @SerialName("initiateLoginUri") val initiateLoginUri: String? = null,
        @EncodeDefault @SerialName("postLogoutRedirectUri") val postLogoutRedirectUris: Set<String>? = null,
        @EncodeDefault @SerialName("requestUris") val requestUris: Set<String>? = null,
        @EncodeDefault @SerialName("description") val description: String = "",
        @EncodeDefault @SerialName("allowIntrospection") val allowIntrospection: Boolean = false,
        @EncodeDefault @SerialName("reuseRefreshToken") val isReuseRefreshToken: Boolean = true,
        @EncodeDefault @SerialName("clearAccessTokensOnRefresh") var isClearAccessTokensOnRefresh: Boolean = true,
        @EncodeDefault @SerialName("dynamicallyRegistered") val isDynamicallyRegistered: Boolean = false,
        @EncodeDefault @SerialName("codeChallengeMethod") var codeChallengeMethod: PKCEAlgorithm? = null,
        @EncodeDefault @SerialName("softwareId") var softwareId: String? = null,
        @EncodeDefault @SerialName("softwareVersion") var softwareVersion: String? = null,
        @EncodeDefault @SerialName("softwareStatement") var softwareStatement: @Serializable(JWTStringConverter::class) JWT? = null,
        @EncodeDefault @SerialName("creationDate") var createdAt: ISODate? = null,
    ) {
        constructor(s: ClientDetailsEntity) : this(
            clientId = requireNotNull(s.clientId) { "Missing client id" },
            resourceIds = s.resourceIds,
            secret = s.clientSecret,
            scope = s.scope,
            authorities = s.authorities.mapTo(HashSet()) {
                it as? GrantedAuthority ?: GrantedAuthority(it.authority)
            },
            accessTokenValiditySeconds = s.accessTokenValiditySeconds,
            refreshTokenValiditySeconds = s.refreshTokenValiditySeconds,
            idTokenValiditySeconds = s.idTokenValiditySeconds,
            deviceCodeValiditySeconds = s.deviceCodeValiditySeconds,
            redirectUris = s.redirectUris,
            claimsRedirectUris = s.claimsRedirectUris,
            clientName = s.clientName,
            clientUri = s.clientUri,
            logoUri = s.logoUri,
            contacts = s.contacts,
            tosUri = s.tosUri,
            tokenEndpointAuthMethod = requireNotNull(s.tokenEndpointAuthMethod) { "Missing authentication method" },
            grantTypes = s.authorizedGrantTypes,
            responseTypes = s.responseTypes,
            policyUri = s.policyUri,
            applicationType = s.applicationType,
            sectorIdentifierUri = s.sectorIdentifierUri,
            subjectType = s.subjectType,
            jwks_uri = s.jwksUri,
            jwks = s.jwks,
            requestObjectSigningAlg = s.requestObjectSigningAlg,
            userInfoEncryptedResponseAlg = s.userInfoEncryptedResponseAlg,
            userInfoEncryptedResponseEnc = s.userInfoEncryptedResponseEnc,
            userInfoSignedResponseAlg = s.userInfoSignedResponseAlg,
            idTokenSignedResponseAlg = s.idTokenSignedResponseAlg,
            idTokenEncryptedResponseAlg = s.idTokenEncryptedResponseAlg,
            idTokenEncryptedResponseEnc = s.idTokenEncryptedResponseEnc,
            tokenEndpointAuthSigningAlg = s.tokenEndpointAuthSigningAlg,
            defaultMaxAge = s.defaultMaxAge,
            requireAuthTime = s.requireAuthTime,
            defaultACRValues = s.defaultACRvalues,
            initiateLoginUri = s.initiateLoginUri,
            postLogoutRedirectUris = s.postLogoutRedirectUris,
            requestUris = s.requestUris,
            description = s.clientDescription,
            allowIntrospection = s.isAllowIntrospection,
            isReuseRefreshToken = s.isReuseRefreshToken,
            isClearAccessTokensOnRefresh = s.isClearAccessTokensOnRefresh,
            isDynamicallyRegistered = s.isDynamicallyRegistered,
            codeChallengeMethod = s.codeChallengeMethod,
            softwareId = s.softwareId,
            softwareVersion = s.softwareVersion,
            softwareStatement = s.softwareStatement,
            createdAt = s.createdAt,
        )

        fun toClientDetailsEntity(): ClientDetailsEntity {
            return ClientDetailsEntity(
                id = null,
                clientId = clientId,
                clientSecret = secret,
                redirectUris = redirectUris,
                clientName = clientName,
                clientUri = clientUri,
                logoUri = logoUri,
                contacts = contacts,
                tosUri = tosUri,
                tokenEndpointAuthMethod = tokenEndpointAuthMethod,
                scope = scope?.toHashSet() ?: hashSetOf(),
                authorizedGrantTypes = grantTypes.toHashSet(),
                responseTypes = responseTypes.toHashSet(),
                policyUri = policyUri,
                jwksUri = jwks_uri,
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
                defaultACRvalues = defaultACRValues,
                initiateLoginUri = initiateLoginUri,
                postLogoutRedirectUris = postLogoutRedirectUris,
                requestUris = requestUris,
                clientDescription = description,
                isReuseRefreshToken = isReuseRefreshToken,
                isDynamicallyRegistered = isDynamicallyRegistered,
                isAllowIntrospection = allowIntrospection,
                idTokenValiditySeconds = idTokenValiditySeconds ?: -1,
                createdAt = createdAt,
                isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh,
                deviceCodeValiditySeconds = deviceCodeValiditySeconds,
                claimsRedirectUris = claimsRedirectUris,
                softwareStatement = softwareStatement,
                codeChallengeMethod = codeChallengeMethod,
            ).also { client ->
                accessTokenValiditySeconds?.let { client.setAccessTokenValiditySeconds(it) }
                refreshTokenValiditySeconds?.let { client.setRefreshTokenValiditySeconds(it) }
                client.setAuthorities(authorities)
                resourceIds?.let { client.setResourceIds(it) }
            }
        }
    }

    interface ConfigurationData {
        val clients: List<ClientDetailsConfiguration>
        val grants: List<ApprovedSite.SerialDelegate>
        val whitelistedSites: List<WhitelistedSite>
        val blacklistedSites: List<BlacklistedSite>
        val authenticationHolders: List<AuthenticationHolderEntity>
        val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>
        val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>
        val systemScopes: List<SystemScope>
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    abstract class ConfigurationDataBase(
        @SerialName("clients")
        @EncodeDefault
        override val clients: List<ClientDetailsConfiguration> = emptyList(),
        @SerialName("grants")
        @EncodeDefault
        override val grants: List<ApprovedSite.SerialDelegate> = emptyList(),
        @SerialName("whitelistedSites")
        @EncodeDefault
        override val whitelistedSites: List<WhitelistedSite> = emptyList(),
        @SerialName("blacklistedSites")
        @EncodeDefault
        override val blacklistedSites: List<BlacklistedSite> = emptyList(),
        @SerialName("accessTokens")
        @EncodeDefault
        override val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
        @SerialName("refreshTokens")
        @EncodeDefault
        override val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
        @SerialName("systemScopes")
        @EncodeDefault
        override val systemScopes: List<SystemScope> = emptyList(),
    ) : ConfigurationData {
    }

    @Serializable
    open class ConfigurationData10 : ConfigurationDataBase {
        @SerialName("authenticationHolders")
        internal val _authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10>

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders.map { AuthenticationHolderEntity.SerialDelegate10(it) }
        }

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
            dummy: Int = 0
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders
        }

        override val authenticationHolders: List<AuthenticationHolderEntity>
            get() = _authenticationHolders.map { it.toAuthenticationHolder() }
    }

    @Serializable
    open class ConfigurationData12 : ConfigurationDataBase {
        @SerialName("authenticationHolders")
        internal val _authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12>

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders.map { AuthenticationHolderEntity.SerialDelegate12(it) }
        }

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
            dummy: Int = 0
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders
        }

        override val authenticationHolders: List<AuthenticationHolderEntity>
            get() = _authenticationHolders.map { it.toAuthenticationHolder() }
    }

    interface ExtendedConfiguration: ConfigurationData {
        val extensions: Map<String, JsonElement>
    }
    
    @Serializable(ExtendedConfiguration10.Companion::class)
    class ExtendedConfiguration10 : ConfigurationData10, ExtendedConfiguration {
        @Transient
        override var extensions: Map<String, JsonElement> = emptyMap()
            private set


        constructor(
            s: ConfigurationData10
        ) : super(
            s.clients, s.grants, s.whitelistedSites, s.blacklistedSites,
            s._authenticationHolders, s.accessTokens, s.refreshTokens, s.systemScopes,
        )

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
            extensions: Map<String, JsonElement> = emptyMap(),
        ) : super(
            clients, grants, whitelistedSites, blacklistedSites,
            authenticationHolders,
            accessTokens, refreshTokens, systemScopes,
        ) {
            this.extensions = extensions
        }

        @OptIn(ExperimentalSerializationApi::class)
        companion object : KSerializer<ExtendedConfiguration10> {
            private val delegate = ConfigurationData10.serializer()
            private val authHoldersSerializer: KSerializer<List<AuthenticationHolderEntity.SerialDelegate10>> =
                ListSerializer(AuthenticationHolderEntity.SerialDelegate10.serializer())

            override val descriptor: SerialDescriptor = buildClassSerialDescriptor(
                "${delegate.descriptor.serialName}.extended"
            ) {
                val dd = delegate.descriptor
                for (elemIdx in 0..<dd.elementsCount) {
                    element(dd.getElementName(elemIdx), dd.getElementDescriptor(elemIdx), dd.getElementAnnotations(elemIdx), dd.isElementOptional(elemIdx))
                }
                element("extensions", ContextualSerializer(Any::class).descriptor, isOptional = true)
            }

            override fun serialize(encoder: Encoder, value: ExtendedConfiguration10) {
                if (encoder !is JsonEncoder) { // Ignore extensions when not in json mode (TODO for now)
                    delegate.serialize(encoder, value)
                } else {
                    val obj = buildJsonObject {
                        for ((k, v) in encoder.json.encodeToJsonElement(delegate, value).jsonObject) {
                            put(k, v)
                        }
                        for ((name, ext) in value.extensions) {
                            put(name, ext)
                        }

                    }
                    encoder.encodeJsonElement(obj)
                }
            }

            override fun deserialize(decoder: Decoder): ExtendedConfiguration10 {
                if (decoder !is JsonDecoder) {
                    return ExtendedConfiguration10(delegate.deserialize(decoder))
                }

                var clients: List<ClientDetailsConfiguration> = emptyList()
                var grants: List<ApprovedSite.SerialDelegate> = emptyList()
                var whitelistedSites: List<WhitelistedSite> = emptyList()
                var blacklistedSites: List<BlacklistedSite> = emptyList()
                var authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10> = emptyList()
                var accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList()
                var refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList()
                var systemScopes: List<SystemScope> = emptyList()
                val extensions = mutableMapOf<String, JsonElement>()


                val obj = decoder.decodeJsonElement().jsonObject

                for ((name, value) in obj) {
                    when (name) {
                        "clients" -> clients = decoder.json.decodeFromJsonElement(value)
                        "grants" -> grants = decoder.json.decodeFromJsonElement(value)
                        "whitelistedSites" -> whitelistedSites = decoder.json.decodeFromJsonElement(value)
                        "blacklistedSites" -> blacklistedSites = decoder.json.decodeFromJsonElement(value)
                        "authenticationHolders" -> authenticationHolders =
                            decoder.json.decodeFromJsonElement(authHoldersSerializer, value)
                        "accessTokens" -> accessTokens = decoder.json.decodeFromJsonElement(value)
                        "refreshTokens" -> refreshTokens = decoder.json.decodeFromJsonElement(value)
                        "systemScopes" -> systemScopes = decoder.json.decodeFromJsonElement(value)
                        else -> extensions[name] = value

                    }
                }

                return ExtendedConfiguration10(clients, grants, whitelistedSites, blacklistedSites,
                                               authenticationHolders, accessTokens, refreshTokens, systemScopes, extensions)
            }
        }
    }

    @Serializable(ExtendedConfiguration12.Companion::class)
    class ExtendedConfiguration12 : ConfigurationData12, ExtendedConfiguration {
        @Transient
        override var extensions: Map<String, JsonElement> = emptyMap()
            private set


        constructor(
            s: ConfigurationData12
        ) : super(
            s.clients, s.grants, s.whitelistedSites, s.blacklistedSites,
            s._authenticationHolders, s.accessTokens, s.refreshTokens, s.systemScopes,
        )

        constructor(
            clients: List<ClientDetailsConfiguration> = emptyList(),
            grants: List<ApprovedSite.SerialDelegate> = emptyList(),
            whitelistedSites: List<WhitelistedSite> = emptyList(),
            blacklistedSites: List<BlacklistedSite> = emptyList(),
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12> = emptyList(),
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList(),
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList(),
            systemScopes: List<SystemScope> = emptyList(),
            extensions: Map<String, JsonElement> = emptyMap(),
        ) : super(
            clients, grants, whitelistedSites, blacklistedSites,
            authenticationHolders,
            accessTokens, refreshTokens, systemScopes,
        ) {
            this.extensions = extensions
        }

        @OptIn(ExperimentalSerializationApi::class)
        companion object : KSerializer<ExtendedConfiguration12> {
            private val delegate = ConfigurationData12.serializer()
            private val authHoldersSerializer =
                ListSerializer(AuthenticationHolderEntity.SerialDelegate12.serializer())

            override val descriptor: SerialDescriptor = buildClassSerialDescriptor(
                "${delegate.descriptor.serialName}.extended"
            ) {
                val dd = delegate.descriptor
                for (elemIdx in 0..<dd.elementsCount) {
                    element(dd.getElementName(elemIdx), dd.getElementDescriptor(elemIdx), dd.getElementAnnotations(elemIdx), dd.isElementOptional(elemIdx))
                }
                element("extensions", ContextualSerializer(Any::class).descriptor, isOptional = true)
            }

            override fun serialize(encoder: Encoder, value: ExtendedConfiguration12) {
                if (encoder !is JsonEncoder) { // Ignore extensions when not in json mode (TODO for now)
                    delegate.serialize(encoder, value)
                } else {
                    val obj = encoder.json.encodeToJsonElement(delegate, value).jsonObject.toMutableMap()
                    for ((name, ext) in value.extensions) {
                        obj[name] = ext
                    }
                    encoder.encodeJsonElement(JsonObject(obj))
                }
            }

            override fun deserialize(decoder: Decoder): ExtendedConfiguration12 {
                if (decoder !is JsonDecoder) {
                    return ExtendedConfiguration12(delegate.deserialize(decoder))
                }

                var clients: List<ClientDetailsConfiguration> = emptyList()
                var grants: List<ApprovedSite.SerialDelegate> = emptyList()
                var whitelistedSites: List<WhitelistedSite> = emptyList()
                var blacklistedSites: List<BlacklistedSite> = emptyList()
                var authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12> = emptyList()
                var accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate> = emptyList()
                var refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate> = emptyList()
                var systemScopes: List<SystemScope> = emptyList()
                val extensions = mutableMapOf<String, JsonElement>()


                val obj = decoder.decodeJsonElement().jsonObject

                for ((name, value) in obj) {
                    when (name) {
                        "clients" -> clients = decoder.json.decodeFromJsonElement(value)
                        "grants" -> grants = decoder.json.decodeFromJsonElement(value)
                        "whitelistedSites" -> whitelistedSites = decoder.json.decodeFromJsonElement(value)
                        "blacklistedSites" -> blacklistedSites = decoder.json.decodeFromJsonElement(value)
                        "authenticationHolders" -> authenticationHolders =
                            decoder.json.decodeFromJsonElement(authHoldersSerializer, value)
                        "accessTokens" -> accessTokens = decoder.json.decodeFromJsonElement(value)
                        "refreshTokens" -> refreshTokens = decoder.json.decodeFromJsonElement(value)
                        "systemScopes" -> systemScopes = decoder.json.decodeFromJsonElement(value)
                        else -> extensions[name] = value

                    }
                }

                return ExtendedConfiguration12(clients, grants, whitelistedSites, blacklistedSites,
                                               authenticationHolders, accessTokens, refreshTokens, systemScopes, extensions)
            }
        }
    }

    companion object {
        private val dateFormatter = DateTimeFormatter.ISO_DATE_TIME.withLocale(Locale.ENGLISH)

        @JvmStatic
        public fun utcToInstant(value: String?): Instant? {
            if (value == null) return null

            try {
                return Instant.from(dateFormatter.parse(value))
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun utcToDate(value: String?): Date? {
            if (value == null) return null

            try {
                return Date.from(Instant.from(dateFormatter.parse(value)))
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun toUTCString(value: Instant?): String? {
            if (value == null) return null

            return dateFormatter.format(value)
        }

        @JvmStatic
        public fun toUTCString(value: Date?): String? {
            if (value == null) return null

            return dateFormatter.format(value.toInstant())
        }

        public fun Any?.warnIgnored(name: String): Nothing? {
            if (this!=null) logger.warn("Attribute $name ignored as unsupported on the service version")
            return null
        }

        public fun Boolean.warnIgnored(name: String, default: Boolean = false): Boolean {
            if (this!=default) logger.warn("Attribute $name ignored as unsupported on the service version")
            return default
        }

        public fun MutableMap<*,*>.warnIgnored(name: String) {
            if (this.isNotEmpty()) logger.warn("Attribute $name ignored as unsupported on the service version")
            clear()
        }

        /**
         * Logger for this class
         */
        private val logger = getLogger<MITREidDataService>()
        val json: Json = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
            prettyPrintIndent = "  "
        }


        /**
         * Data member for 1.X configurations
         */
        const val MITREID_CONNECT_1_0: String = "mitreid-connect-1.0"
        const val MITREID_CONNECT_1_1: String = "mitreid-connect-1.1"
        const val MITREID_CONNECT_1_2: String = "mitreid-connect-1.2"
        const val MITREID_CONNECT_1_3: String = "mitreid-connect-1.3"

        // member names
        const val REFRESHTOKENS: String = "refreshTokens"
        const val ACCESSTOKENS: String = "accessTokens"
        const val WHITELISTEDSITES: String = "whitelistedSites"
        const val BLACKLISTEDSITES: String = "blacklistedSites"
        const val AUTHENTICATIONHOLDERS: String = "authenticationHolders"
        const val GRANTS: String = "grants"
        const val CLIENTS: String = "clients"
        const val SYSTEMSCOPES: String = "systemScopes"

        private val DUMMY_AUTH_HOLDER = AuthenticationHolderEntity()
    }
}

class DataServiceContext(
    val version: String,
    val clientRepository: OAuth2ClientRepository,
    val approvedSiteRepository: ApprovedSiteRepository,
    val wlSiteRepository: WhitelistedSiteRepository,
    val blSiteRepository: BlacklistedSiteRepository,
    val authHolderRepository: org.mitre.oauth2.repository.AuthenticationHolderRepository,
    val tokenRepository: OAuth2TokenRepository,
    val sysScopeRepository: SystemScopeRepository,
    val extensions: List<MITREidDataServiceExtension>,
    val maps: MITREidDataServiceMaps,
)
