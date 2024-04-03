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
package org.mitre.openid.connect.service.impl

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.AuthenticationHolderEntity
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.SavedUserAuthentication
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
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.JsonUtils.readMap
import org.mitre.util.JsonUtils.readSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.stereotype.Service
import java.io.IOException
import java.text.ParseException

/**
 *
 * Data service to import MITREid 1.0 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_0 : MITREidDataServiceSupport(), MITREidDataService {
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
    private var extensions = emptyList<MITREidDataServiceExtension>()

    private val maps = MITREidDataServiceMaps()

    override fun supportsVersion(version: String?): Boolean {
        return THIS_VERSION == version
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataService#export(com.google.gson.stream.JsonWriter)
	 */
    @Throws(IOException::class)
    override fun exportData(writer: JsonWriter) {
        throw UnsupportedOperationException("Can not export 1.0 format from this version.")
    }

    override fun importData(configJson: String) {
//        maps.clearAll() // for safety/correctness
        val conf = json.decodeFromString<ConfigurationData_1_0>(configJson)
        conf.clients?.let { readClients(it) }
        conf.grants?.let { readGrants(it) }
        conf.whitelistedSites?.let { readWhitelistedSites(it) }
        conf.blacklistedSites?.let { readBlacklistedSites(it) }
        conf.authenticationHolders?.let { readAuthenticationHolders(it) }
        conf.accessTokens?.let { readAccessTokens(it) }
        conf.refreshTokens?.let { readRefreshTokens(it) }
        conf.systemScopes?.let { readSystemScopes(it) }
        // TODO readExtensions(conf)
        fixObjectReferences()
        // TODO fixExtensionObjectReferences(maps)
        maps.clearAll()
/*
    fixObjectReferences()
    for (extension in extensions) {
        if (extension.supportsVersion(THIS_VERSION)) {
            extension.fixExtensionObjectReferences(maps)
            break
        }
    }
    maps.clearAll()
*/


//        super.importData(configJson)
    }

    /* (non-Javadoc)
         * @see org.mitre.openid.connect.service.MITREidDataService#importData(com.google.gson.stream.JsonReader)
         */
    @Throws(IOException::class)
    override fun importData(reader: JsonReader) {
        logger.info("Reading configuration for 1.0")

        // this *HAS* to start as an object
        reader.beginObject()

        while (reader.hasNext()) {
            val tok = reader.peek()
            when (tok) {
                JsonToken.NAME -> {
                    val name = reader.nextName()
                    // find out which member it is
                    if (name == MITREidDataService.CLIENTS) {
                        readClients(reader)
                    } else if (name == MITREidDataService.GRANTS) {
                        readGrants(reader)
                    } else if (name == MITREidDataService.WHITELISTEDSITES) {
                        readWhitelistedSites(reader)
                    } else if (name == MITREidDataService.BLACKLISTEDSITES) {
                        readBlacklistedSites(reader)
                    } else if (name == MITREidDataService.AUTHENTICATIONHOLDERS) {
                        readAuthenticationHolders(reader)
                    } else if (name == MITREidDataService.ACCESSTOKENS) {
                        readAccessTokens(reader)
                    } else if (name == MITREidDataService.REFRESHTOKENS) {
                        readRefreshTokens(reader)
                    } else if (name == MITREidDataService.SYSTEMSCOPES) {
                        readSystemScopes(reader)
                    } else {
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
        fixObjectReferences()
        for (extension in extensions) {
            if (extension.supportsVersion(THIS_VERSION)) {
                extension.fixExtensionObjectReferences(maps)
                break
            }
        }
        maps.clearAll()
    }

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
                        } else if (name == "id") {
                            currentId = reader.nextLong()
                        } else if (name == "expiration") {
                            val date = utcToDate(reader.nextString())
                            token.expiration = date
                        } else if (name == "value") {
                            val value = reader.nextString()
                            try {
                                token.jwt = JWTParser.parse(value)
                            } catch (ex: ParseException) {
                                logger.error("Unable to set refresh token value to {}", value, ex)
                            }
                        } else if (name == "clientId") {
                            clientId = reader.nextString()
                        } else if (name == "authenticationHolderId") {
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
                        } else if (name == "id") {
                            currentId = reader.nextLong()
                        } else if (name == "expiration") {
                            val date = utcToDate(reader.nextString())
                            token.expiration = date
                        } else if (name == "value") {
                            val value = reader.nextString()
                            try {
                                // all tokens are JWTs
                                token.jwt = JWTParser.parse(value)
                            } catch (ex: ParseException) {
                                logger.error("Unable to set refresh token value to {}", value, ex)
                            }
                        } else if (name == "clientId") {
                            clientId = reader.nextString()
                        } else if (name == "authenticationHolderId") {
                            authHolderId = reader.nextLong()
                        } else if (name == "refreshTokenId") {
                            refreshTokenId = reader.nextLong()
                        } else if (name == "scope") {
                            val scope = readSet<String>(reader)
                            token.scope = scope
                        } else if (name == "type") {
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
            reader.endObject()
            requireNotNull(currentId)
            requireNotNull(clientId)
            requireNotNull(authHolderId)
            val newId = tokenRepository.saveAccessToken(token).id!!
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
                        } else if (name == "id") {
                            currentId = reader.nextLong()
                        } else if (name == "ownerId") {
                            //not needed
                            reader.skipValue()
                        } else if (name == "authentication") {
                            var clientAuthorization: OAuth2Request? = null
                            var userAuthentication: Authentication? = null
                            reader.beginObject()
                            while (reader.hasNext()) {
                                when (reader.peek()) {
                                    JsonToken.END_OBJECT -> continue
                                    JsonToken.NAME -> {
                                        val subName = reader.nextName()
                                        when {
                                            reader.peek() == JsonToken.NULL ->
                                                reader.skipValue()

                                            subName == "clientAuthorization" ->
                                                clientAuthorization = readAuthorizationRequest(reader)

                                                // skip binary encoded version
                                            subName == "userAuthentication" ->
                                                reader.skipValue()

                                            subName == "savedUserAuthentication" ->
                                                userAuthentication = readSavedUserAuthentication(reader)

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
                            val auth = OAuth2Authentication(clientAuthorization, userAuthentication)
                            ahe.authentication = auth
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
            val newId = authHolderRepository.save(ahe).id!!
            maps.authHolderOldToNewIdMap[currentId] = newId
            logger.debug("Read authentication holder {}", currentId)
        }
        reader.endArray()
        logger.info("Done reading authentication holders")
    }

    //used by readAuthenticationHolders
    @Throws(IOException::class)
    private fun readAuthorizationRequest(reader: JsonReader): OAuth2Request {
        var scope: Set<String> = LinkedHashSet()
        var resourceIds: Set<String> = HashSet()
        var approved = false
        var authorities: MutableCollection<GrantedAuthority> = HashSet()
        var authorizationParameters: Map<String, String> = HashMap()
        var responseTypes: Set<String> = HashSet()
        var redirectUri: String? = null
        var clientId: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.peek()) {
                JsonToken.END_OBJECT -> continue
                JsonToken.NAME -> {
                    val name = reader.nextName()
                    if (reader.peek() == JsonToken.NULL) {
                        reader.skipValue()
                    } else if (name == "authorizationParameters") {
                        authorizationParameters = readMap<String>(reader)
                    } else if (name == "approvalParameters") {
                        reader.skipValue()
                    } else if (name == "clientId") {
                        clientId = reader.nextString()
                    } else if (name == "scope") {
                        scope = readSet<String>(reader)
                    } else if (name == "resourceIds") {
                        resourceIds = readSet<String>(reader)
                    } else if (name == "authorities") {
                        val authorityStrs = readSet<String>(reader)
                        authorities = HashSet()
                        for (s in authorityStrs) {
                            val ga: GrantedAuthority = SimpleGrantedAuthority(s)
                            authorities.add(ga)
                        }
                    } else if (name == "approved") {
                        approved = reader.nextBoolean()
                    } else if (name == "denied") {
                        if (approved == false) {
                            approved = !reader.nextBoolean()
                        }
                    } else if (name == "redirectUri") {
                        redirectUri = reader.nextString()
                    } else if (name == "responseTypes") {
                        responseTypes = readSet<String>(reader)
                    } else {
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
        return OAuth2Request(authorizationParameters, clientId, authorities, approved, scope, resourceIds, redirectUri, responseTypes, null)
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
                    } else if (name == "name") {
                        savedUserAuth.setName(reader.nextString())
                    } else if (name == "sourceClass") {
                        savedUserAuth.sourceClass = reader.nextString()
                    } else if (name == "authenticated") {
                        savedUserAuth.isAuthenticated = reader.nextBoolean()
                    } else if (name == "authorities") {
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
            var whitelistedSiteId: Long? = null
            var tokenIds: Set<Long>? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == "id") {
                            currentId = reader.nextLong()
                        } else if (name == "accessDate") {
                            val date = utcToDate(reader.nextString())
                            site.accessDate = date
                        } else if (name == "clientId") {
                            site.clientId = reader.nextString()
                        } else if (name == "creationDate") {
                            val date = utcToDate(reader.nextString())
                            site.creationDate = date
                        } else if (name == "timeoutDate") {
                            val date = utcToDate(reader.nextString())
                            site.timeoutDate = date
                        } else if (name == "userId") {
                            site.userId = reader.nextString()
                        } else if (name == "allowedScopes") {
                            val allowedScopes = readSet<String>(reader)
                            site.allowedScopes = allowedScopes
                        } else if (name == "whitelistedSiteId") {
                            whitelistedSiteId = reader.nextLong()
                        } else if (name == "approvedAccessTokens") {
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
            val newId = approvedSiteRepository.save(site).id!!
            maps.grantOldToNewIdMap[currentId] = newId
            if (whitelistedSiteId != null) {
                logger.debug("Ignoring whitelisted site marker on approved site.")
            }
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
                    JsonToken.NAME -> when (reader.nextName()) {
                        "id" -> currentId = reader.nextLong()

                        "clientId" -> wlSite.clientId = reader.nextString()

                        "creatorUserId" -> wlSite.creatorUserId = reader.nextString()

                        "allowedScopes" -> {
                            val allowedScopes = readSet<String>(reader)
                            wlSite.allowedScopes = allowedScopes
                        }

                        else -> {
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
            val newId = wlSiteRepository.save(wlSite).id!!
            maps.whitelistedSiteOldToNewIdMap[currentId] = newId
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
                        if (name == "id") {
                            reader.skipValue()
                        } else if (name == "uri") {
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
                            name == "clientId" -> client.clientId = reader.nextString()
                            name == "resourceIds" -> client.resourceIds = readSet(reader)
                            name == "secret" -> client.clientSecret = reader.nextString()
                            name == "scope" -> client.setScope(readSet(reader))

                            name == "authorities" -> client.authorities = readSet<String>(reader)
                                .mapTo(HashSet()) { SimpleGrantedAuthority(it) }

                            name == "accessTokenValiditySeconds" ->
                                client.accessTokenValiditySeconds = reader.nextInt()

                            name == "refreshTokenValiditySeconds" ->
                                client.refreshTokenValiditySeconds = reader.nextInt()

                            name == "redirectUris" ->
                                client.redirectUris = readSet(reader)

                            name == "name" ->
                                client.clientName = reader.nextString()

                            name == "uri" ->
                                client.clientUri = reader.nextString()

                            name == "logoUri" ->
                                client.logoUri = reader.nextString()

                            name == "contacts" ->
                                client.contacts = readSet(reader)

                            name == "tosUri" ->
                                client.tosUri = reader.nextString()

                            name == "tokenEndpointAuthMethod" ->
                                client.tokenEndpointAuthMethod = AuthMethod.getByValue(reader.nextString())

                            name == "grantTypes" ->
                                client.grantTypes = readSet<String>(reader).toMutableSet()

                            name == "responseTypes" ->
                                client.responseTypes = readSet<String>(reader).toMutableSet()

                            name == "policyUri" ->
                                client.policyUri = reader.nextString()

                            name == "applicationType" ->
                                client.applicationType = AppType.valueOf(reader.nextString())

                            name == "sectorIdentifierUri" ->
                                client.sectorIdentifierUri = reader.nextString()

                            name == "subjectType" ->
                                client.subjectType = SubjectType.getByValue(reader.nextString())

                            name == "jwks_uri" ->
                                client.jwksUri = reader.nextString()

                            name == "requestObjectSigningAlg" ->
                                client.requestObjectSigningAlg = JWSAlgorithm.parse(reader.nextString())

                            name == "userInfoEncryptedResponseAlg" ->
                                client.userInfoEncryptedResponseAlg = JWEAlgorithm.parse(reader.nextString())

                            name == "userInfoEncryptedResponseEnc" ->
                                client.userInfoEncryptedResponseEnc = EncryptionMethod.parse(reader.nextString())

                            name == "userInfoSignedResponseAlg" ->
                                client.userInfoSignedResponseAlg = JWSAlgorithm.parse(reader.nextString())

                            name == "idTokenSignedResonseAlg" ->
                                client.idTokenSignedResponseAlg = JWSAlgorithm.parse(reader.nextString())

                            name == "idTokenEncryptedResponseAlg" ->
                                client.idTokenEncryptedResponseAlg = JWEAlgorithm.parse(reader.nextString())

                            name == "idTokenEncryptedResponseEnc" ->
                                client.idTokenEncryptedResponseEnc = EncryptionMethod.parse(reader.nextString())

                            name == "tokenEndpointAuthSigningAlg" ->
                                client.tokenEndpointAuthSigningAlg = JWSAlgorithm.parse(reader.nextString())

                            name == "defaultMaxAge" -> client.defaultMaxAge = reader.nextInt()
                            name == "requireAuthTime" -> client.requireAuthTime = reader.nextBoolean()
                            name == "defaultACRValues" ->
                                client.defaultACRvalues = readSet(reader)

                            name == "initiateLoginUri" -> client.initiateLoginUri = reader.nextString()

                            name == "postLogoutRedirectUri" ->
                                client.postLogoutRedirectUris = hashSetOf(reader.nextString())

                            name == "requestUris" -> client.requestUris = readSet(reader)
                            name == "description" -> client.clientDescription = reader.nextString()
                            name == "allowIntrospection" -> client.isAllowIntrospection = reader.nextBoolean()
                            name == "reuseRefreshToken" -> client.isReuseRefreshToken = reader.nextBoolean()
                            name == "dynamicallyRegistered" -> client.isDynamicallyRegistered = reader.nextBoolean()
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
                            name == "value" -> scope.value = reader.nextString()
                            name == "description" -> scope.description = reader.nextString()
                            // previously "allowDynReg" scopes are now tagged as "not restricted" and vice versa
                            name == "allowDynReg" -> scope.isRestricted = !reader.nextBoolean()
                            name == "defaultScope" -> scope.isDefaultScope = reader.nextBoolean()
                            name == "icon" -> scope.icon = reader.nextString()
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

    private fun readRefreshTokens(tokenDelegates: List<OAuth2RefreshTokenEntity.SerialDelegate>) {

        for (delegate in tokenDelegates) {

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
        logger.info("Done reading refresh tokens")
    }

    private fun readAccessTokens(config: List<OAuth2AccessTokenEntity.SerialDelegate>) {
        for (delegate in config) {
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

        logger.info("Done reading access tokens")
    }

    @Throws(IOException::class)
    private fun readAuthenticationHolders(holders: List<AuthenticationHolderEntity>) {
        for (ahe in holders) {
            val currentId: Long = requireNotNull(ahe.id) { "Missing id for authentication holder" }
            ahe.id = null

            val newId = authHolderRepository.save(ahe).id!!
            maps.authHolderOldToNewIdMap[currentId] = newId
            logger.debug("Read authentication holder {}", currentId)
        }
        logger.info("Done reading authentication holders")
    }

    @Throws(IOException::class)
    private fun readGrants(config: List<ApprovedSite.SerialDelegate>) {
        for (delegate in config) {

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
        logger.info("Done reading grants")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readWhitelistedSites(sites: List<WhitelistedSite>) {
        for (wlSite in sites) {
            val currentId: Long = wlSite.id!!
            wlSite.id = null // reset to null

            requireNotNull(currentId)
            val newId = wlSiteRepository.save(wlSite).id!!
            maps.whitelistedSiteOldToNewIdMap[currentId] = newId
        }
        logger.info("Done reading whitelisted sites")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readBlacklistedSites(sites: List<BlacklistedSite>) {
        for (blSite in sites) {
            blSite.id = null // ignore ID
            blSiteRepository.save(blSite)
        }
        logger.info("Done reading blacklisted sites")
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readClients(config: List<ClientDetailsConfiguration>) {
        for (client in config) {
            clientRepository.saveClient(client.toClientDetailsEntity())
        }
        logger.info("Done reading clients")
    }

    /**
     * Read the list of system scopes from the reader and insert them into the
     * scope repository.
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readSystemScopes(scopes: List<SystemScope>) {
        for (scope in scopes) {
            sysScopeRepository.save(scope)
        }

        logger.info("Done reading system scopes")
    }

    private fun fixObjectReferences() {
        for ((oldRefreshTokenId, clientRef) in maps.refreshTokenToClientRefs) {
            val client = clientRepository.getClientByClientId(clientRef)
            val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.client = client
            tokenRepository.saveRefreshToken(refreshToken)
        }

        for ((oldRefreshTokenId, oldAuthHolderId) in maps.refreshTokenToAuthHolderRefs) {
            val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId]
            val authHolder = authHolderRepository.getById(newAuthHolderId)
            val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.authenticationHolder = authHolder!!
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
        @SerialName("tokenEndpointAuthMethod") val tokenEndpointAuthMethod: AuthMethod = AuthMethod.SECRET_BASIC,
        @SerialName("grantTypes") val grantTypes: Set<String> = hashSetOf(),
        @SerialName("responseTypes") val responseTypes: Set<String> = hashSetOf(),
        @SerialName("policyUri") val policyUri: String? = null,
        @SerialName("applicationType") val applicationType: AppType = AppType.WEB,
        @SerialName("sectorIdentifierUri") val sectorIdentifierUri: String? = null,
        @SerialName("subjectType") val subjectType: SubjectType? = null,
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
    class ConfigurationData_1_0(
        @SerialName(MITREidDataService.CLIENTS)
        val clients: List<ClientDetailsConfiguration>? = null,
        @SerialName(MITREidDataService.GRANTS)
        val grants: List<ApprovedSite.SerialDelegate>? = null,
        @SerialName(MITREidDataService.WHITELISTEDSITES)
        val whitelistedSites: List<WhitelistedSite>? = null,
        @SerialName(MITREidDataService.BLACKLISTEDSITES)
        val blacklistedSites: List<BlacklistedSite>? = null,
        @SerialName(MITREidDataService.AUTHENTICATIONHOLDERS)
        val authenticationHolders: List<AuthenticationHolderEntity>? = null,
        @SerialName(MITREidDataService.ACCESSTOKENS)
        val accessTokens: List<OAuth2AccessTokenEntity.SerialDelegate>? = null,
        @SerialName(MITREidDataService.REFRESHTOKENS)
        val refreshTokens: List<OAuth2RefreshTokenEntity.SerialDelegate>? = null,
        @SerialName(MITREidDataService.SYSTEMSCOPES)
        val systemScopes: List<SystemScope>? = null,
    ) : MITREidDataService.ConfigurationData {

    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService_1_0::class.java)
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_0
    }
}
