/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.openid.connect.service.impl

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTParser
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.util.requireId
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.utcToDate
import org.mitre.openid.connect.service.MITREidDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataService.Context
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.JsonUtils.readMap
import org.mitre.util.JsonUtils.readSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Service
import java.io.IOException
import java.text.ParseException

/**
 *
 * Data service to import and export MITREid 1.2 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_2 : MITREidDataService {
    @Autowired
    private lateinit var clientRepository: OAuth2ClientRepository

    @Autowired
    private lateinit var approvedSiteRepository: ApprovedSiteRepository

    @Autowired
    private lateinit var wlSiteRepository: WhitelistedSiteRepository

    @Autowired
    private lateinit var blSiteRepository: BlacklistedSiteRepository

    @Autowired
    private lateinit var authHolderRepository: AuthenticationHolderRepository

    @Autowired
    private lateinit var tokenRepository: OAuth2TokenRepository

    @Autowired
    private lateinit var sysScopeRepository: SystemScopeRepository

    @Autowired(required = false)
    private val extensions = emptyList<MITREidDataServiceExtension>()

    private val maps = MITREidDataServiceMaps()

    override fun supportsVersion(version: String?): Boolean {
        return THIS_VERSION == version
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataService#export(com.google.gson.stream.JsonWriter)
	 */
    @Throws(IOException::class)
    override fun exportData(writer: JsonWriter) {
        throw UnsupportedOperationException("Can not export 1.2 format from this version.")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataService#importData(com.google.gson.stream.JsonReader)
	 */
    @Throws(IOException::class)
    override fun importData(reader: JsonReader) {
        logger.info("Reading configuration for 1.2")

        // this *HAS* to start as an object
        reader.beginObject()

        while (reader.hasNext()) {
            val tok = reader.peek()
            when (tok) {
                JsonToken.NAME -> {
                    // find out which member it is
                    when (val name = reader.nextName()) {
                        MITREidDataService.CLIENTS -> readClients(reader)
                        MITREidDataService.GRANTS -> readGrants(reader)
                        MITREidDataService.WHITELISTEDSITES -> readWhitelistedSites(reader)
                        MITREidDataService.BLACKLISTEDSITES -> readBlacklistedSites(reader)
                        MITREidDataService.AUTHENTICATIONHOLDERS -> readAuthenticationHolders(reader)
                        MITREidDataService.ACCESSTOKENS -> readAccessTokens(reader)
                        MITREidDataService.REFRESHTOKENS -> readRefreshTokens(reader)
                        MITREidDataService.SYSTEMSCOPES -> readSystemScopes(reader)
                        else -> {
                            for (extension in extensions) {
                                if (extension.supportsVersion(THIS_VERSION)) {
                                    extension.importExtensionData(name, reader)
                                    break
                                }
                            }
                            // unknown token, skip it
                            reader.skipValue()
                        }
                    }
                }

                JsonToken.END_OBJECT -> {
                    // the object ended, we're done here
                    reader.endObject()
                    continue
                }

                else -> {
                    logger.debug("Found unexpected entry")
                    reader.skipValue()
                    continue
                }
            }
        }
        val context = Context(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        fixObjectReferences(context)
        for (extension in extensions) {
            if (extension.supportsVersion(THIS_VERSION)) {
                extension.fixExtensionObjectReferences(maps)
                break
            }
        }
        maps.clearAll()
    }
    /**
     * @throws IOException
     */
    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readRefreshTokens(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val token = OAuth2RefreshTokenEntity()
            reader.beginObject()
            var currentId: Long? = null
            var clientId: String? = null
            var authHolderId: Long? = null
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ID) {
                            currentId = reader.nextLong()
                        } else if (name == EXPIRATION) {
                            val date = utcToDate(reader.nextString())
                            token.expiration = date
                        } else if (name == VALUE) {
                            val value = reader.nextString()
                            try {
                                token.jwt = JWTParser.parse(value)
                            } catch (ex: ParseException) {
                                logger.error("Unable to set refresh token value to {}", value, ex)
                            }
                        } else if (name == CLIENT_ID) {
                            clientId = reader.nextString()
                        } else if (name == AUTHENTICATION_HOLDER_ID) {
                            authHolderId = reader.nextLong()
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            requireNotNull(currentId)
            requireNotNull(clientId)
            requireNotNull(authHolderId)
            val newId = tokenRepository.saveRefreshToken(token).id!!
            maps.refreshTokenToClientRefs[currentId] = clientId
            maps.refreshTokenToAuthHolderRefs[currentId] = authHolderId
            maps.refreshTokenOldToNewIdMap[currentId] = newId
            logger.debug("Read refresh token {}", currentId)
        }
        reader.endArray()
        logger.info("Done reading refresh tokens")
    }
    /**
     * @throws IOException
     */
    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readAccessTokens(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val token = OAuth2AccessTokenEntity()
            reader.beginObject()
            var currentId: Long? = null
            var clientId: String? = null
            var authHolderId: Long? = null
            var refreshTokenId: Long? = null
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ID) {
                            currentId = reader.nextLong()
                        } else if (name == EXPIRATION) {
                            val date = utcToDate(reader.nextString())
                            token.expiration = date
                        } else if (name == VALUE) {
                            val value = reader.nextString()
                            try {
                                // all tokens are JWTs
                                token.jwt = JWTParser.parse(value)
                            } catch (ex: ParseException) {
                                logger.error("Unable to set refresh token value to {}", value, ex)
                            }
                        } else if (name == CLIENT_ID) {
                            clientId = reader.nextString()
                        } else if (name == AUTHENTICATION_HOLDER_ID) {
                            authHolderId = reader.nextLong()
                        } else if (name == REFRESH_TOKEN_ID) {
                            refreshTokenId = reader.nextLong()
                        } else if (name == SCOPE) {
                            val scope = readSet<String>(reader)
                            token.scope = scope
                        } else if (name == TYPE) {
                            token.tokenType = reader.nextString()
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            requireNotNull(currentId)
            requireNotNull(clientId)
            requireNotNull(authHolderId)
            reader.endObject()
            val newId = tokenRepository.saveAccessToken(token).id !!
            maps.accessTokenToClientRefs[currentId] = clientId
            maps.accessTokenToAuthHolderRefs[currentId] = authHolderId
            if (refreshTokenId != null) {
                maps.accessTokenToRefreshTokenRefs[currentId] = refreshTokenId
            }
            maps.accessTokenOldToNewIdMap[currentId] = newId
            logger.debug("Read access token {}", currentId)
        }
        reader.endArray()
        logger.info("Done reading access tokens")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readAuthenticationHolders(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val ahe = AuthenticationHolderEntity()
            reader.beginObject()
            var currentId: Long? = null
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ID) {
                            currentId = reader.nextLong()
                        } else if (name == REQUEST_PARAMETERS) {
                            ahe.requestParameters = readMap(reader)
                        } else if (name == CLIENT_ID) {
                            ahe.clientId = reader.nextString()
                        } else if (name == SCOPE) {
                            ahe.scope = readSet(reader)
                        } else if (name == RESOURCE_IDS) {
                            ahe.resourceIds = readSet(reader)
                        } else if (name == AUTHORITIES) {
                            val authorityStrs = readSet<String>(reader)
                            val authorities: MutableSet<GrantedAuthority> = HashSet()
                            for (s in authorityStrs) {
                                val ga: GrantedAuthority = SimpleGrantedAuthority(s)
                                authorities.add(ga)
                            }
                            ahe.authorities = authorities
                        } else if (name == APPROVED) {
                            ahe.isApproved = reader.nextBoolean()
                        } else if (name == REDIRECT_URI) {
                            ahe.redirectUri = reader.nextString()
                        } else if (name == RESPONSE_TYPES) {
                            ahe.responseTypes = readSet(reader)
                        } else if (name == EXTENSIONS) {
                            ahe.extensions = readMap(reader)
                        } else if (name == SAVED_USER_AUTHENTICATION) {
                            ahe.userAuth = readSavedUserAuthentication(reader)
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            val newId = authHolderRepository.save(ahe).id
            maps.authHolderOldToNewIdMap[currentId!!] = newId!!
            logger.debug("Read authentication holder {}", currentId)
        }
        reader.endArray()
        logger.info("Done reading authentication holders")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readSavedUserAuthentication(reader: JsonReader): SavedUserAuthentication {
        val savedUserAuth = SavedUserAuthentication()
        reader.beginObject()

        while (reader.hasNext()) {
            when (reader.peek()) {
                JsonToken.END_OBJECT -> continue
                JsonToken.NAME -> {
                    val name = reader.nextName()
                    if (reader.peek() == JsonToken.NULL) {
                        reader.skipValue()
                    } else if (name == NAME) {
                        savedUserAuth.setName(reader.nextString())
                    } else if (name == SOURCE_CLASS) {
                        savedUserAuth.sourceClass = reader.nextString()
                    } else if (name == AUTHENTICATED) {
                        savedUserAuth.isAuthenticated = reader.nextBoolean()
                    } else if (name == AUTHORITIES) {
                        val authorityStrs = readSet<String>(reader)
                        val authorities: MutableSet<GrantedAuthority> = HashSet()
                        for (s in authorityStrs) {
                            val ga: GrantedAuthority = SimpleGrantedAuthority(s)
                            authorities.add(ga)
                        }
                        savedUserAuth.authorities = authorities
                    } else {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                    }
                }

                else -> {
                    logger.debug("Found unexpected entry")
                    reader.skipValue()
                    continue
                }
            }
        }

        reader.endObject()
        return savedUserAuth
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readGrants(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val site = ApprovedSite()
            var currentId: Long? = null
            var tokenIds: Set<Long>? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ID) {
                            currentId = reader.nextLong()
                        } else if (name == ACCESS_DATE) {
                            val date = utcToDate(reader.nextString())
                            site.accessDate = date
                        } else if (name == CLIENT_ID) {
                            site.clientId = reader.nextString()
                        } else if (name == CREATION_DATE) {
                            val date = utcToDate(reader.nextString())
                            site.creationDate = date
                        } else if (name == TIMEOUT_DATE) {
                            val date = utcToDate(reader.nextString())
                            site.timeoutDate = date
                        } else if (name == USER_ID) {
                            site.userId = reader.nextString()
                        } else if (name == ALLOWED_SCOPES) {
                            val allowedScopes = readSet<String>(reader)
                            site.allowedScopes = allowedScopes
                        } else if (name == APPROVED_ACCESS_TOKENS) {
                            tokenIds = readSet<Long>(reader)
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            requireNotNull(currentId)
            val newId = approvedSiteRepository.save(site).id
            maps.grantOldToNewIdMap[currentId] = newId!!
            if (tokenIds != null) {
                maps.grantToAccessTokensRefs[currentId] = tokenIds
            }
            logger.debug("Read grant {}", currentId)
        }
        reader.endArray()
        logger.info("Done reading grants")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readWhitelistedSites(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val wlSite = WhitelistedSite()
            var currentId: Long? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (name == ID) {
                            currentId = reader.nextLong()
                        } else if (name == CLIENT_ID) {
                            wlSite.clientId = reader.nextString()
                        } else if (name == CREATOR_USER_ID) {
                            wlSite.creatorUserId = reader.nextString()
                        } else if (name == ALLOWED_SCOPES) {
                            val allowedScopes = readSet<String>(reader)
                            wlSite.allowedScopes = allowedScopes
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            val newId = wlSiteRepository.save(wlSite).id
            maps.whitelistedSiteOldToNewIdMap[currentId!!] = newId!!
        }
        reader.endArray()
        logger.info("Done reading whitelisted sites")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readBlacklistedSites(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val blSite = BlacklistedSite()
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (name == ID) {
                            reader.skipValue()
                        } else if (name == URI) {
                            blSite.uri = reader.nextString()
                        } else {
                            logger.debug("Found unexpected entry")
                            reader.skipValue()
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            blSiteRepository.save(blSite)
        }
        reader.endArray()
        logger.info("Done reading blacklisted sites")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readClients(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val client = ClientDetailsEntity()
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        when {
                            reader.peek() == JsonToken.NULL -> reader.skipValue()
                            name == CLIENT_ID -> client.clientId = reader.nextString()
                            name == RESOURCE_IDS -> client.resourceIds = readSet<String>(reader).toHashSet()
                            name == SECRET -> client.clientSecret = reader.nextString()
                            name == SCOPE -> client.setScope(readSet(reader))

                            name == AUTHORITIES -> client.authorities =
                                readSet<String>(reader).mapTo(HashSet()) { SimpleGrantedAuthority(it) }

                            name == ACCESS_TOKEN_VALIDITY_SECONDS ->
                                client.accessTokenValiditySeconds = reader.nextInt()

                            name == REFRESH_TOKEN_VALIDITY_SECONDS ->
                                client.refreshTokenValiditySeconds = reader.nextInt()

                            name == REDIRECT_URIS ->
                                client.redirectUris = readSet(reader)

                            name == CLAIMS_REDIRECT_URIS ->
                                client.claimsRedirectUris = readSet(reader)

                            name == NAME -> client.clientName = reader.nextString()
                            name == URI -> client.clientUri = reader.nextString()
                            name == LOGO_URI -> client.logoUri = reader.nextString()
                            name == CONTACTS -> client.contacts = readSet(reader)
                            name == TOS_URI -> client.tosUri = reader.nextString()

                            name == TOKEN_ENDPOINT_AUTH_METHOD ->
                                client.tokenEndpointAuthMethod = AuthMethod.getByValue(reader.nextString())

                            name == GRANT_TYPES -> client.grantTypes = readSet<String>(reader).toHashSet()

                            name == RESPONSE_TYPES ->
                                client.responseTypes = readSet<String>(reader).toHashSet()

                            name == POLICY_URI -> client.policyUri = reader.nextString()

                            name == APPLICATION_TYPE -> client.applicationType = AppType.valueOf(reader.nextString())

                            name == SECTOR_IDENTIFIER_URI ->
                                client.sectorIdentifierUri = reader.nextString()

                            name == SUBJECT_TYPE ->
                                client.subjectType = SubjectType.getByValue(reader.nextString())

                            name == JWKS_URI -> client.jwksUri = reader.nextString()

                            name == JWKS -> {
                                try {
                                    client.jwks = JWKSet.parse(reader.nextString())
                                } catch (e: ParseException) {
                                    logger.error("Couldn't parse JWK Set", e)
                                }
                            }
                            name == REQUEST_OBJECT_SIGNING_ALG ->
                                client.requestObjectSigningAlg = JWSAlgorithm.parse(reader.nextString())

                            name == USER_INFO_ENCRYPTED_RESPONSE_ALG ->
                                client.userInfoEncryptedResponseAlg = JWEAlgorithm.parse(reader.nextString())

                            name == USER_INFO_ENCRYPTED_RESPONSE_ENC ->
                                client.userInfoEncryptedResponseEnc = EncryptionMethod.parse(reader.nextString())

                            name == USER_INFO_SIGNED_RESPONSE_ALG ->
                                client.userInfoSignedResponseAlg = JWSAlgorithm.parse(reader.nextString())

                            name == ID_TOKEN_SIGNED_RESPONSE_ALG ->
                                client.idTokenSignedResponseAlg = JWSAlgorithm.parse(reader.nextString())

                            name == ID_TOKEN_ENCRYPTED_RESPONSE_ALG ->
                                client.idTokenEncryptedResponseAlg = JWEAlgorithm.parse(reader.nextString())

                            name == ID_TOKEN_ENCRYPTED_RESPONSE_ENC ->
                                client.idTokenEncryptedResponseEnc = EncryptionMethod.parse(reader.nextString())

                            name == TOKEN_ENDPOINT_AUTH_SIGNING_ALG ->
                                client.tokenEndpointAuthSigningAlg = JWSAlgorithm.parse(reader.nextString())

                            name == DEFAULT_MAX_AGE -> client.defaultMaxAge = reader.nextInt()
                            name == REQUIRE_AUTH_TIME -> client.requireAuthTime = reader.nextBoolean()
                            name == DEFAULT_ACR_VALUES -> client.defaultACRvalues = readSet(reader)
                            name == "initiateLoginUri" -> client.initiateLoginUri = reader.nextString()

                            name == POST_LOGOUT_REDIRECT_URI ->
                                client.postLogoutRedirectUris = readSet(reader)

                            name == REQUEST_URIS -> client.requestUris = readSet(reader)
                            name == DESCRIPTION -> client.clientDescription = reader.nextString()
                            name == ALLOW_INTROSPECTION -> client.isAllowIntrospection = reader.nextBoolean()
                            name == REUSE_REFRESH_TOKEN -> client.isReuseRefreshToken = reader.nextBoolean()
                            name == CLEAR_ACCESS_TOKENS_ON_REFRESH ->
                                client.isClearAccessTokensOnRefresh = reader.nextBoolean()

                            name == DYNAMICALLY_REGISTERED ->
                                client.isDynamicallyRegistered = reader.nextBoolean()

                            else -> {
                                logger.debug("Found unexpected entry")
                                reader.skipValue()
                            }
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            clientRepository.saveClient(client)
        }
        reader.endArray()
        logger.info("Done reading clients")
    }

    /**
     * Read the list of system scopes from the reader and insert them into the
     * scope repository.
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readSystemScopes(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            val scope = SystemScope()
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        when {
                            reader.peek() == JsonToken.NULL -> reader.skipValue()
                            name == VALUE -> scope.value = reader.nextString()
                            name == DESCRIPTION -> scope.description = reader.nextString()
                            name == RESTRICTED -> scope.isRestricted = reader.nextBoolean()
                            name == DEFAULT_SCOPE -> scope.isDefaultScope = reader.nextBoolean()
                            name == ICON -> scope.icon = reader.nextString()
                            name == STRUCTURED -> logger.warn("Found a structured scope, ignoring structure")
                            name == STRUCTURED_PARAMETER -> logger.warn("Found a structured scope, ignoring structure")
                            else -> {
                                logger.debug("found unexpected entry")
                                reader.skipValue()
                            }
                        }
                    }

                    else -> {
                        logger.debug("Found unexpected entry")
                        reader.skipValue()
                        continue
                    }
                }
            }
            reader.endObject()
            sysScopeRepository.save(scope)
        }
        reader.endArray()
        logger.info("Done reading system scopes")
    }

    override fun importClient(context: Context, client: MITREidDataService.ClientDetailsConfiguration) {
        with(client) {
            // New in 1.3
            codeChallengeMethod = codeChallengeMethod.warnIgnored("codeChallengeMethod")
            softwareId = softwareId.warnIgnored("softwareId")
            softwareVersion = softwareVersion.warnIgnored("softwareVersion")
            softwareStatement = softwareStatement.warnIgnored("softwareStatement")
            createdAt = createdAt.warnIgnored("createdAt")
        }

        super.importClient(context, client)
    }

    override fun importGrant(context: Context, delegate: ApprovedSite.SerialDelegate) {
        with(delegate) {
            whitelistedSiteId = whitelistedSiteId.warnIgnored("whitelistedSiteId")
        }
        super.importGrant(context, delegate)
    }

    override fun fixObjectReferences(context: Context) {
        logger.info("Fixing object references...")
        for (oldRefreshTokenId in context.maps.refreshTokenToClientRefs.keys) {
            val clientRef = context.maps.refreshTokenToClientRefs[oldRefreshTokenId]
            val client = context.clientRepository.getClientByClientId(clientRef!!)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.client = client
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for (oldRefreshTokenId in context.maps.refreshTokenToAuthHolderRefs.keys) {
            val oldAuthHolderId = context.maps.refreshTokenToAuthHolderRefs[oldRefreshTokenId]
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId]
            val authHolder = context.authHolderRepository.getById(newAuthHolderId)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.authenticationHolder = authHolder!!
            context.tokenRepository.saveRefreshToken(refreshToken)
        }
        for (oldAccessTokenId in context.maps.accessTokenToClientRefs.keys) {
            val clientRef = context.maps.accessTokenToClientRefs[oldAccessTokenId]
            val client = context.clientRepository.getClientByClientId(clientRef!!)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.client = client
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for (oldAccessTokenId in context.maps.accessTokenToAuthHolderRefs.keys) {
            val oldAuthHolderId = context.maps.accessTokenToAuthHolderRefs[oldAccessTokenId]
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId] ?: error("Missing authHolder map $oldAuthHolderId")
            val authHolder = context.authHolderRepository.getById(newAuthHolderId) ?: error("Missing authHolder $newAuthHolderId")
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId].requireId()
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in context.maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId] ?: error("Missing map for old refresh token: $oldRefreshTokenId")
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.refreshToken = refreshToken
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for (oldGrantId in context.maps.grantToAccessTokensRefs.keys) {
            val oldAccessTokenIds = context.maps.grantToAccessTokensRefs[oldGrantId]!!

            val newGrantId = context.maps.grantOldToNewIdMap[oldGrantId]!!
            val site = context.approvedSiteRepository.getById(newGrantId)

            for (oldTokenId in oldAccessTokenIds) {
                val newTokenId = context.maps.accessTokenOldToNewIdMap[oldTokenId]?: error("Missing map $oldTokenId")
                val token = context.tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                context.tokenRepository.saveAccessToken(token)
            }

            context.approvedSiteRepository.save(site!!)
        }
        logger.info("Done fixing object references.")
    }

    companion object {
        private const val DEFAULT_SCOPE = "defaultScope"
        private const val STRUCTURED_PARAMETER = "structuredParameter"
        private const val STRUCTURED = "structured"
        private const val RESTRICTED = "restricted"
        private const val ICON = "icon"
        private const val DYNAMICALLY_REGISTERED = "dynamicallyRegistered"
        private const val CLEAR_ACCESS_TOKENS_ON_REFRESH = "clearAccessTokensOnRefresh"
        private const val REUSE_REFRESH_TOKEN = "reuseRefreshToken"
        private const val ALLOW_INTROSPECTION = "allowIntrospection"
        private const val DESCRIPTION = "description"
        private const val REQUEST_URIS = "requestUris"
        private const val POST_LOGOUT_REDIRECT_URI = "postLogoutRedirectUri"
        private const val INTITATE_LOGIN_URI = "intitateLoginUri"
        private const val DEFAULT_ACR_VALUES = "defaultACRValues"
        private const val REQUIRE_AUTH_TIME = "requireAuthTime"
        private const val DEFAULT_MAX_AGE = "defaultMaxAge"
        private const val TOKEN_ENDPOINT_AUTH_SIGNING_ALG = "tokenEndpointAuthSigningAlg"
        private const val USER_INFO_ENCRYPTED_RESPONSE_ENC = "userInfoEncryptedResponseEnc"
        private const val USER_INFO_ENCRYPTED_RESPONSE_ALG = "userInfoEncryptedResponseAlg"
        private const val USER_INFO_SIGNED_RESPONSE_ALG = "userInfoSignedResponseAlg"
        private const val ID_TOKEN_ENCRYPTED_RESPONSE_ENC = "idTokenEncryptedResponseEnc"
        private const val ID_TOKEN_ENCRYPTED_RESPONSE_ALG = "idTokenEncryptedResponseAlg"
        private const val ID_TOKEN_SIGNED_RESPONSE_ALG = "idTokenSignedResponseAlg"
        private const val REQUEST_OBJECT_SIGNING_ALG = "requestObjectSigningAlg"
        private const val SUBJECT_TYPE = "subjectType"
        private const val SECTOR_IDENTIFIER_URI = "sectorIdentifierUri"
        private const val APPLICATION_TYPE = "applicationType"
        private const val JWKS = "jwks"
        private const val JWKS_URI = "jwksUri"
        private const val POLICY_URI = "policyUri"
        private const val GRANT_TYPES = "grantTypes"
        private const val TOKEN_ENDPOINT_AUTH_METHOD = "tokenEndpointAuthMethod"
        private const val TOS_URI = "tosUri"
        private const val CONTACTS = "contacts"
        private const val LOGO_URI = "logoUri"
        private const val REDIRECT_URIS = "redirectUris"
        private const val REFRESH_TOKEN_VALIDITY_SECONDS = "refreshTokenValiditySeconds"
        private const val ACCESS_TOKEN_VALIDITY_SECONDS = "accessTokenValiditySeconds"
        private const val SECRET = "secret"
        private const val URI = "uri"
        private const val CREATOR_USER_ID = "creatorUserId"
        private const val APPROVED_ACCESS_TOKENS = "approvedAccessTokens"
        private const val ALLOWED_SCOPES = "allowedScopes"
        private const val USER_ID = "userId"
        private const val TIMEOUT_DATE = "timeoutDate"
        private const val CREATION_DATE = "creationDate"
        private const val ACCESS_DATE = "accessDate"
        private const val AUTHENTICATED = "authenticated"
        private const val SOURCE_CLASS = "sourceClass"
        private const val NAME = "name"
        private const val SAVED_USER_AUTHENTICATION = "savedUserAuthentication"
        private const val EXTENSIONS = "extensions"
        private const val RESPONSE_TYPES = "responseTypes"
        private const val REDIRECT_URI = "redirectUri"
        private const val APPROVED = "approved"
        private const val AUTHORITIES = "authorities"
        private const val RESOURCE_IDS = "resourceIds"
        private const val REQUEST_PARAMETERS = "requestParameters"
        private const val TYPE = "type"
        private const val SCOPE = "scope"
        private const val REFRESH_TOKEN_ID = "refreshTokenId"
        private const val VALUE = "value"
        private const val AUTHENTICATION_HOLDER_ID = "authenticationHolderId"
        private const val CLIENT_ID = "clientId"
        private const val EXPIRATION = "expiration"
        private const val CLAIMS_REDIRECT_URIS = "claimsRedirectUris"
        private const val ID = "id"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService_1_2::class.java)
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_2
    }
}
