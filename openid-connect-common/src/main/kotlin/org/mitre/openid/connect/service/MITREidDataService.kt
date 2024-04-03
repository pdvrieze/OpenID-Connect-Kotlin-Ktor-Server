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
import java.io.StringReader
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
     * Read in the state from a string
     */
    fun importData(configJson: String) {
        val reader = JsonReader(StringReader(configJson))
        importData(reader)
    }

    /**
     * Return true if the this data service supports the given version. This is called before
     * handing the service the reader through its importData function.
     *
     */
    fun supportsVersion(version: String?): Boolean

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
        @SerialName("claimsRedirectUris") val claimsRedirectUris: Set<String>? = null,
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
        @SerialName("jwks") val jwks: @Serializable(JWKSetStringConverter::class) JWKSet? = null,
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
        @SerialName("clearAccessTokensOnRefresh") val isClearAccessTokensOnRefresh: Boolean = true,
        @SerialName("dynamicallyRegistered") val isDynamicallyRegistered: Boolean = false,
        @SerialName("codeChallengeMethod") val codeChallengeMethod: PKCEAlgorithm? = null,
        @SerialName("softwareId") val softwareId: String? = null,
        @SerialName("softwareVersion") val softwareVersion: String? = null,
        @SerialName("softwareStatement") val softwareStatement: @Serializable(JWTStringConverter::class) JWT? = null,
        @SerialName("creationDate") val createdAt: ISODate? = null,
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

    @Serializable
    open class ConfigurationData(
        @SerialName("clients")
        val clients: List<ClientDetailsConfiguration>? = null,
        @SerialName("grants")
        val grants: List<ApprovedSite.SerialDelegate>? = null,
        @SerialName("whitelistedSites")
        val whitelistedSites: List<WhitelistedSite>? = null,
        @SerialName("blacklistedSites")
        val blacklistedSites: List<BlacklistedSite>? = null,
        @SerialName("authenticationHolders")
        val authenticationHolders: List<AuthenticationHolderEntity>? = null,
        @SerialName("accessTokens")
        val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
        @SerialName("refreshTokens")
        val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
        @SerialName("systemScopes")
        val systemScopes: List<SystemScope>? = null,
    )

    @Serializable(ExtendedConfiguration.Companion::class)
    class ExtendedConfiguration : ConfigurationData {
        @Transient
        var extensions: Map<String, JsonElement> = emptyMap()
            private set


        constructor(
            s: ConfigurationData
        ) : super(
            s.clients, s.grants, s.whitelistedSites, s.blacklistedSites,
            s.authenticationHolders, s.accessTokens, s.refreshTokens, s.systemScopes,
        )

        constructor(
            clients: List<ClientDetailsConfiguration>? = null,
            grants: List<ApprovedSite.SerialDelegate>? = null,
            whitelistedSites: List<WhitelistedSite>? = null,
            blacklistedSites: List<BlacklistedSite>? = null,
            authenticationHolders: List<AuthenticationHolderEntity>? = null,
            accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
            refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
            systemScopes: List<SystemScope>? = null,
            extensions: Map<String, JsonElement> = emptyMap(),
        ) : super(
            clients, grants, whitelistedSites, blacklistedSites,
            authenticationHolders, accessTokens, refreshTokens, systemScopes,
        ) {
            this.extensions = extensions
        }

        @OptIn(ExperimentalSerializationApi::class)
        companion object : KSerializer<ExtendedConfiguration> {
            private val delegate = ConfigurationData.serializer()
            override val descriptor: SerialDescriptor = buildClassSerialDescriptor(
                "${delegate.descriptor.serialName}.extended"
            ) {
                val dd = delegate.descriptor
                for (elemIdx in 0..<dd.elementsCount) {
                    element(dd.getElementName(elemIdx), dd.getElementDescriptor(elemIdx), dd.getElementAnnotations(elemIdx), dd.isElementOptional(elemIdx))
                }
                element("extensions", ContextualSerializer(Any::class).descriptor, isOptional = true)
            }

            override fun serialize(encoder: Encoder, value: ExtendedConfiguration) {
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

            override fun deserialize(decoder: Decoder): ExtendedConfiguration {
                if (decoder !is JsonDecoder) {
                    return ExtendedConfiguration(delegate.deserialize(decoder))
                }

                var clients: List<ClientDetailsConfiguration>? = null
                var grants: List<ApprovedSite.SerialDelegate>? = null
                var whitelistedSites: List<WhitelistedSite>? = null
                var blacklistedSites: List<BlacklistedSite>? = null
                var authenticationHolders: List<AuthenticationHolderEntity>? = null
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
                        "authenticationHolders" -> authenticationHolders = decoder.json.decodeFromJsonElement(value)
                        "accessTokens" -> accessTokens = decoder.json.decodeFromJsonElement(value)
                        "refreshTokens" -> refreshTokens = decoder.json.decodeFromJsonElement(value)
                        "systemScopes" -> systemScopes = decoder.json.decodeFromJsonElement(value)
                        else -> extensions[name] = value

                    }
                }

                return ExtendedConfiguration(clients, grants, whitelistedSites, blacklistedSites,
                                             authenticationHolders, accessTokens, refreshTokens, systemScopes, extensions)
            }
        }
    }

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

/*
    abstract class ConfigurationSerializerBase<T: ConfigurationData>(val name: String, val version: String, val extensions: List<MITREidDataServiceExtension>) : KSerializer<T> {

        private val elementSerializers: List<Pair<String, KSerializer<*>>> by lazy {
            buildList {
                addBaseElements()
            }
        }


        override val descriptor: SerialDescriptor by lazy {
            buildClassSerialDescriptor(name) {
                for((name, serializer) in elementSerializers) {
                    element(name, serializer.descriptor)
                }
            }
        }

        open fun MutableList<ElementSerializer>.addBaseElements() {
            add(ElementSerializer(CLIENTS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(GRANTS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(WHITELISTEDSITES, ListSerializer(WhitelistedSite.serializer()), false))
            add(ElementSerializer(BLACKLISTEDSITES, ListSerializer(BlacklistedSite.serializer()), false))
            add(ElementSerializer(AUTHENTICATIONHOLDERS, ListSerializer(AuthenticationHolderEntity.serializer()), false))
            add(ElementSerializer(ACCESSTOKENS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(REFRESHTOKENS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(SYSTEMSCOPES, ListSerializer(SystemScope.serializer()), false))
        }

    }
*/

    @Throws(IOException::class)
    fun Context.readClients(config: List<ClientDetailsConfiguration>): Unit = TODO()
    @Throws(IOException::class)
    fun Context.readGrants(config: List<ApprovedSite.SerialDelegate>): Unit = TODO()
    @Throws(IOException::class)
    fun Context.readWhitelistedSites(sites: List<WhitelistedSite>): Unit = TODO()
    @Throws(IOException::class)
    fun Context.readBlacklistedSites(sites: List<BlacklistedSite>): Unit = TODO()
    @Throws(IOException::class)
    fun Context.readAuthenticationHolders(holders: List<AuthenticationHolderEntity>): Unit = TODO()
    fun Context.readAccessTokens(config: List<OAuth2AccessTokenEntity.SerialDelegate>): Unit = TODO()
    fun Context.readRefreshTokens(tokenDelegates: List<OAuth2RefreshTokenEntity.SerialDelegate>): Unit = TODO()
    @Throws(IOException::class)
    fun Context.readSystemScopes(scopes: List<SystemScope>): Unit = TODO()
    fun Context.fixObjectReferences(): Unit = TODO()

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
}

internal data class ElementSerializer(val name: String, val serializer: KSerializer<*>, val isOptional: Boolean)
