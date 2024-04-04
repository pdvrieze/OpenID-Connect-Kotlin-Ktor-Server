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

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import kotlinx.serialization.ContextualSerializer
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
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.model.convert.JWEAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWEEncryptionMethodStringConverter
import org.mitre.oauth2.model.convert.JWKSetStringConverter
import org.mitre.oauth2.model.convert.JWSAlgorithmStringConverter
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.mitre.oauth2.repository.AuthenticationHolderRepository
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
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.io.IOException
import java.text.ParseException
import java.time.Instant
import java.util.*

/**
 * @author jricher
 * @author arielak
 */
interface MITREidDataService {
    /**
     * Write out the current server state to the given JSON writer as a JSON object
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    fun exportData(writer: JsonWriter)

    /**
     * Read in the current server state from the given JSON reader as a JSON object
     */
    @Throws(IOException::class)
    fun importData(reader: JsonReader)

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


    fun Context.importData(conf: ExtendedConfiguration) {
        conf.clients?.let {
            for (client in it) importClient(this, client)
            logger.info("Done reading clients")
        }
        conf.grants?.let {
            for (delegate in it) importGrant(this, delegate)
            logger.info("Done reading grants")
        }
        conf.whitelistedSites?.let {
            for (wlSite in it) importWhitelistedSite(this, wlSite)
            logger.info("Done reading whitelisted sites")
        }
        conf.blacklistedSites?.let {
            for (blSite in it) importBlacklistedSite(this, blSite)
            logger.info("Done reading blacklisted sites")
        }
        conf.authenticationHolders?.let {
            for (ahe in it) importAuthenticationHolder(this, ahe)
            logger.info("Done reading authentication holders")
        }
        conf.accessTokens?.let {
            for (delegate in it) importAccessToken(this, delegate)
            logger.info("Done reading access tokens")
        }
        conf.refreshTokens?.let {
            for (delegate in it) importRefreshToken(this, delegate)
            logger.info("Done reading refresh tokens")
        }
        conf.systemScopes?.let {
            for (scope in it) importSystemScope(this, scope)
            logger.info("Done reading system scopes")
        }
        // TODO readExtensions(conf)
        fixObjectReferences(this)
        // TODO fixExtensionObjectReferences(maps)
        maps.clearAll()
        /*
    for (extension in extensions) {
        if (extension.supportsVersion(THIS_VERSION)) {
            extension.fixExtensionObjectReferences(maps)
            break
        }
    }
    maps.clearAll()
*/
    }

    fun importClient(context: Context, client: ClientDetailsConfiguration) {
        context.clientRepository.saveClient(client.toClientDetailsEntity())
    }

    fun importGrant(context: Context, delegate: ApprovedSite.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId

            if (delegate.whitelistedSiteId != null) {
                logger.debug("Ignoring whitelisted site marker on approved site.")
            }

            val tokenIds: Set<Long>? = delegate.approvedAccessTokens

            val site = ApprovedSite().apply {
                accessDate = delegate.accessDate
                clientId = delegate.clientId
                creationDate = delegate.creationDate
                timeoutDate = delegate.timeoutDate
                userId = delegate.userId
                allowedScopes = delegate.allowedScopes
            }

            val newId = approvedSiteRepository.save(site).id!!
            maps.grantOldToNewIdMap[currentId] = newId

            if (tokenIds != null) {
                maps.grantToAccessTokensRefs[currentId] = tokenIds
            }
            logger.debug("Read grant {}", currentId)
        }
    }

    fun importWhitelistedSite(context: Context, wlSite: WhitelistedSite) {
        with(context) {
            val currentId: Long = wlSite.id!!
            wlSite.id = null // reset to null

            requireNotNull(currentId)
            val newId = wlSiteRepository.save(wlSite).id!!
            maps.whitelistedSiteOldToNewIdMap[currentId] = newId
        }
    }

    fun importBlacklistedSite(context: Context, blSite: BlacklistedSite) {
        blSite.id = null // ignore ID
        context.blSiteRepository.save(blSite)
    }

    fun importAuthenticationHolder(context: Context, ahe: AuthenticationHolderEntity) {
        with(context) {
            val currentId: Long = requireNotNull(ahe.id) { "Missing id for authentication holder" }
            ahe.id = null

            val newId = authHolderRepository.save(ahe).id!!
            maps.authHolderOldToNewIdMap[currentId] = newId
            logger.debug("Read authentication holder {}", currentId)
        }
    }

    fun importAccessToken(context: Context, delegate: OAuth2AccessTokenEntity.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId
            val clientId: String = delegate.clientId
            val authHolderId: Long = delegate.authenticationHolderId
            val refreshTokenId: Long? = delegate.refreshTokenId

            val token = OAuth2AccessTokenEntity().apply {
                expiration = delegate.expiration
                jwt = delegate.value
                scope = delegate.scope
                tokenType = delegate.tokenType
            }


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

    fun importRefreshToken(context: Context, delegate: OAuth2RefreshTokenEntity.SerialDelegate) {
        with(context) {
            val currentId: Long = delegate.currentId
            val clientId: String = delegate.clientId
            val authHolderId: Long = delegate.authenticationHolderId

            val token = OAuth2RefreshTokenEntity().apply {
                expiration = delegate.expiration
                jwt = delegate.value
            }

            val newId = tokenRepository.saveRefreshToken(token).id!!

            maps.refreshTokenToClientRefs[currentId] = clientId
            maps.refreshTokenToAuthHolderRefs[currentId] = authHolderId
            maps.refreshTokenOldToNewIdMap[currentId] = newId
            logger.debug("Read refresh token {}", currentId)
        }
    }

    fun importSystemScope(context: Context, scope: SystemScope) {
        context.sysScopeRepository.save(scope)
    }

    fun fixObjectReferences(context: Context) {
        with(context) {
            for ((oldRefreshTokenId, clientRef) in maps.refreshTokenToClientRefs) {
                val client = clientRepository.getClientByClientId(clientRef)
                val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
                val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
                refreshToken.client = client
                tokenRepository.saveRefreshToken(refreshToken)
            }

            for ((oldRefreshTokenId, oldAuthHolderId) in maps.refreshTokenToAuthHolderRefs) {
                val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId]
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
                accessToken.client = client
                tokenRepository.saveAccessToken(accessToken)
            }
            for ((oldAccessTokenId, oldAuthHolderId) in maps.accessTokenToAuthHolderRefs) {
                val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId]
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
                val accessToken = tokenRepository.getAccessTokenById(newAccessTokenId)!!
                accessToken.refreshToken = refreshToken
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

    @Serializable
    class ClientDetailsConfiguration(
        @SerialName("clientId") val clientId: String,
        @SerialName("resourceIds") val resourceIds: Set<String>? = null,
        @SerialName("secret") val secret: String? = null,
        @SerialName("scope") val scope: Set<String>? = null,
        @SerialName("authorities") val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) SimpleGrantedAuthority>? = null,
        @SerialName("accessTokenValiditySeconds") val accessTokenValiditySeconds: Int? = null,
        @SerialName("refreshTokenValiditySeconds") val refreshTokenValiditySeconds: Int? = null,
        @SerialName("idTokenValiditySeconds") val idTokenValiditySeconds: Int? = null,
        @SerialName("deviceTokenValiditySeconds") val deviceCodeValiditySeconds: Int? = null,
        @SerialName("redirectUris") val redirectUris: Set<String> = hashSetOf(),
        @SerialName("claimsRedirectUris") var claimsRedirectUris: Set<String>? = null,
        @SerialName("name") val clientName: String? = null,
        @SerialName("uri") val clientUri: String? = null,
        @SerialName("logoUri") val logoUri: String? = null,
        @SerialName("contacts") val contacts: Set<String>? = null,
        @SerialName("tosUri") val tosUri: String? = null,
        @SerialName("tokenEndpointAuthMethod") val tokenEndpointAuthMethod: ClientDetailsEntity.AuthMethod = ClientDetailsEntity.AuthMethod.SECRET_BASIC,
        @SerialName("grantTypes") val grantTypes: Set<String> = hashSetOf(),
        @SerialName("responseTypes") val responseTypes: Set<String> = hashSetOf(),
        @SerialName("policyUri") val policyUri: String? = null,
        @SerialName("applicationType") val applicationType: ClientDetailsEntity.AppType = ClientDetailsEntity.AppType.WEB,
        @SerialName("sectorIdentifierUri") val sectorIdentifierUri: String? = null,
        @SerialName("subjectType") val subjectType: ClientDetailsEntity.SubjectType? = null,
        @SerialName("jwks_uri") val jwks_uri: String? = null,
        @SerialName("jwks") var jwks: @Serializable(JWKSetStringConverter::class) JWKSet? = null,
        @SerialName("requestObjectSigningAlg") val requestObjectSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName("userInfoEncryptedResponseAlg") val userInfoEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName("userInfoEncryptedResponseEnc") val userInfoEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName("userInfoSignedResponseAlg") val userInfoSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName("idTokenSignedResonseAlg") val idTokenSignedResponseAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName("idTokenEncryptedResponseAlg") val idTokenEncryptedResponseAlg: @Serializable(JWEAlgorithmStringConverter::class) JWEAlgorithm? = null,
        @SerialName("idTokenEncryptedResponseEnc") val idTokenEncryptedResponseEnc: @Serializable(JWEEncryptionMethodStringConverter::class) EncryptionMethod? = null,
        @SerialName("tokenEndpointAuthSigningAlg") val tokenEndpointAuthSigningAlg: @Serializable(JWSAlgorithmStringConverter::class) JWSAlgorithm? = null,
        @SerialName("defaultMaxAge") val defaultMaxAge: Int? = null,
        @SerialName("requireAuthTime") val requireAuthTime: Boolean? = null,
        @SerialName("defaultACRValues") val defaultACRValues: Set<String>? = null,
        @SerialName("initiateLoginUri") val initiateLoginUri: String? = null,
        @SerialName("postLogoutRedirectUri") val postLogoutRedirectUris: Set<String>? = null,
        @SerialName("requestUris") val requestUris: Set<String>? = null,
        @SerialName("description") val description: String = "",
        @SerialName("allowIntrospection") val allowIntrospection: Boolean = false,
        @SerialName("reuseRefreshToken") val isReuseRefreshToken: Boolean = true,
        @SerialName("clearAccessTokensOnRefresh") var isClearAccessTokensOnRefresh: Boolean = true,
        @SerialName("dynamicallyRegistered") val isDynamicallyRegistered: Boolean = false,
        @SerialName("codeChallengeMethod") var codeChallengeMethod: PKCEAlgorithm? = null,
        @SerialName("softwareId") var softwareId: String? = null,
        @SerialName("softwareVersion") var softwareVersion: String? = null,
        @SerialName("softwareStatement") var softwareStatement: @Serializable(JWTStringConverter::class) JWT? = null,
        @SerialName("creationDate") var createdAt: ISODate? = null,
    ) {
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
                grantTypes = grantTypes.toHashSet(),
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
                idTokenValiditySeconds = idTokenValiditySeconds,
                createdAt = createdAt,
                isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh,
                deviceCodeValiditySeconds = deviceCodeValiditySeconds,
                claimsRedirectUris = claimsRedirectUris,
                softwareStatement = softwareStatement,
                codeChallengeMethod = codeChallengeMethod,
            ).also { client ->
                accessTokenValiditySeconds?.run { client.accessTokenValiditySeconds = this }
                refreshTokenValiditySeconds?.run { client.refreshTokenValiditySeconds = this }
                authorities?.run { client.authorities = this }
                resourceIds?.run { client.resourceIds = this }
            }
        }
    }

    interface ConfigurationData {
        val clients: List<ClientDetailsConfiguration>?
        val grants: List<ApprovedSite.SerialDelegate>?
        val whitelistedSites: List<WhitelistedSite>?
        val blacklistedSites: List<BlacklistedSite>?
        val authenticationHolders: List<AuthenticationHolderEntity>?
        val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>?
        val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>?
        val systemScopes: List<SystemScope>?
    }

    @Serializable
    abstract class ConfigurationDataBase(
        @SerialName("clients")
        override val clients: List<ClientDetailsConfiguration>? = null,
        @SerialName("grants")
        override val grants: List<ApprovedSite.SerialDelegate>? = null,
        @SerialName("whitelistedSites")
        override val whitelistedSites: List<WhitelistedSite>? = null,
        @SerialName("blacklistedSites")
        override val blacklistedSites: List<BlacklistedSite>? = null,
        @SerialName("accessTokens")
        override val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
        @SerialName("refreshTokens")
        override val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
        @SerialName("systemScopes")
        override val systemScopes: List<SystemScope>? = null,
    ) : ConfigurationData {
    }

    @Serializable
    open class ConfigurationData10 : ConfigurationDataBase {
        @SerialName("authenticationHolders")
        internal val _authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10>?

        constructor(
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders?.map { AuthenticationHolderEntity.SerialDelegate10(it) }
        }

        constructor(
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
            dummy: Int = 0
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders
        }

        override val authenticationHolders: List<AuthenticationHolderEntity>?
            get() = _authenticationHolders?.map { it.toAuthenticationHolder() }
    }

    @Serializable
    open class ConfigurationData12 : ConfigurationDataBase {
        @SerialName("authenticationHolders")
        internal val _authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12>?

        constructor(
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders?.map { AuthenticationHolderEntity.SerialDelegate12(it) }
        }

        constructor(
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
            dummy: Int = 0
        ) : super(clients, grants,whitelistedSites, blacklistedSites, accessTokens, refreshTokens, systemScopes) {
            _authenticationHolders = authenticationHolders
        }

        override val authenticationHolders: List<AuthenticationHolderEntity>?
            get() = _authenticationHolders?.map { it.toAuthenticationHolder() }
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
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
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
                    val obj = encoder.json.encodeToJsonElement(delegate, value).jsonObject.toMutableMap()
                    for ((name, ext) in value.extensions) {
                        obj[name] = ext
                    }
                    encoder.encodeJsonElement(JsonObject(obj))
                }
            }

            override fun deserialize(decoder: Decoder): ExtendedConfiguration10 {
                if (decoder !is JsonDecoder) {
                    return ExtendedConfiguration10(delegate.deserialize(decoder))
                }

                var clients: List<ClientDetailsConfiguration>? = null
                var grants: List<ApprovedSite.SerialDelegate>? = null
                var whitelistedSites: List<WhitelistedSite>? = null
                var blacklistedSites: List<BlacklistedSite>? = null
                var authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate10>? = null
                var accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null
                var refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null
                var systemScopes: List<SystemScope>? = null
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
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
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

                var clients: List<ClientDetailsConfiguration>? = null
                var grants: List<ApprovedSite.SerialDelegate>? = null
                var whitelistedSites: List<WhitelistedSite>? = null
                var blacklistedSites: List<BlacklistedSite>? = null
                var authenticationHolders: List<AuthenticationHolderEntity.SerialDelegate12>? = null
                var accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null
                var refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null
                var systemScopes: List<SystemScope>? = null
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

    class Context(
        val clientRepository: OAuth2ClientRepository,
        val approvedSiteRepository: ApprovedSiteRepository,
        val wlSiteRepository: WhitelistedSiteRepository,
        val blSiteRepository: BlacklistedSiteRepository,
        val authHolderRepository: AuthenticationHolderRepository,
        val tokenRepository: OAuth2TokenRepository,
        val sysScopeRepository: SystemScopeRepository,
        val extensions: List<MITREidDataServiceExtension>,
        val maps: MITREidDataServiceMaps,
    )

    companion object {
        private val dateFormatter = DateFormatter().apply {
            setIso(DateTimeFormat.ISO.DATE_TIME)
        }

        @JvmStatic
        public fun utcToInstant(value: String?): Instant? {
            if (value == null) return null

            try {
                return dateFormatter.parse(value, Locale.ENGLISH).toInstant()
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun utcToDate(value: String?): Date? {
            if (value == null) return null

            try {
                return dateFormatter.parse(value, Locale.ENGLISH)
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun toUTCString(value: Instant?): String? {
            if (value == null) return null

            return dateFormatter.print(Date.from(value), Locale.ENGLISH)
        }

        @JvmStatic
        public fun toUTCString(value: Date?): String? {
            if (value == null) return null

            return dateFormatter.print(value, Locale.ENGLISH)
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
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService::class.java)
        val json: Json = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
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
    }

}
