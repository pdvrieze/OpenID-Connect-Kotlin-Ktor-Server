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
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request
import org.springframework.stereotype.Service
import java.io.IOException
import java.io.Serializable
import java.text.ParseException

/**
 *
 * Data service to import MITREid 1.1 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_1 : MITREidDataService {
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
        throw UnsupportedOperationException("Can not export 1.1 format from this version.")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataService#importData(com.google.gson.stream.JsonReader)
	 */
    @Throws(IOException::class)
    override fun importData(reader: JsonReader) {
        logger.info("Reading configuration for 1.1")

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
                                if (extension.supportsVersion(THIS_VERSION)) {
                                    extension.importExtensionData(name, reader)
                                    break
                                }
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
                                                reader.skipValue() // skip null values
                                            
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
        var requestParameters: Map<String, String> = HashMap()
        var responseTypes: Set<String> = HashSet()
        val extensions: MutableMap<String, Serializable> = HashMap()
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
                    } else if (name == "requestParameters") {
                        requestParameters = readMap<String>(reader)
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
                    } else if (name == "extensions") {
                        // skip the binary encoded version
                        reader.skipValue()
                    } else if (name == "extensionStrings") {
                        val extEnc = readMap<String>(reader)
                        for ((key, value) in extEnc) {
                            extensions[key] = value
                        }
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
        return OAuth2Request(requestParameters, clientId, authorities, approved, scope, resourceIds, redirectUri, responseTypes, extensions)
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
                            name == "structured" -> logger.warn("Found a structured scope, ignoring structure")
                            name == "structuredParameter" -> logger.warn("Found a structured scope, ignoring structure")
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

    override fun importData(config: MITREidDataService.ExtendedConfiguration) {
        val context = Context(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        context.importData(config)
    }

    override fun importData(configJson: String) {
        importData(MITREidDataService.json.decodeFromString<MITREidDataService.ExtendedConfiguration10>(configJson))
    }

    override fun importClient(context: Context, client: MITREidDataService.ClientDetailsConfiguration) {
        with(client) {
            // New in 1.2
            claimsRedirectUris = claimsRedirectUris.warnIgnored("claimsRedirectUris")
            jwks = jwks.warnIgnored("jwks")
            isClearAccessTokensOnRefresh = isClearAccessTokensOnRefresh
                .takeIf { it==false }.warnIgnored("isClearAccessTokensOnRefresh") ?: true

            // New in 1.3
            codeChallengeMethod = codeChallengeMethod.warnIgnored("codeChallengeMethod")
            softwareId = softwareId.warnIgnored("softwareId")
            softwareVersion = softwareVersion.warnIgnored("softwareVersion")
            softwareStatement = softwareStatement.warnIgnored("softwareStatement")
            createdAt = createdAt.warnIgnored("createdAt")
        }

        super.importClient(context, client)
    }

    override fun fixObjectReferences(context: Context) {
        for ((oldRefreshTokenId, clientRef) in context.maps.refreshTokenToClientRefs) {
            val client = context.clientRepository.getClientByClientId(clientRef)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.client = client
            context.tokenRepository.saveRefreshToken(refreshToken)
        }

        for ((oldRefreshTokenId, oldAuthHolderId) in context.maps.refreshTokenToAuthHolderRefs) {
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId]
            val authHolder = context.authHolderRepository.getById(newAuthHolderId)
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)!!
            refreshToken.authenticationHolder = authHolder!!
            context.tokenRepository.saveRefreshToken(refreshToken)
        }

        for ((oldAccessTokenId, clientRef) in context.maps.accessTokenToClientRefs) {
            val client = context.clientRepository.getClientByClientId(clientRef)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.client = client
            context.tokenRepository.saveAccessToken(accessToken)
        }
        context.maps.accessTokenToClientRefs.clear()
        for ((oldAccessTokenId, oldAuthHolderId) in context.maps.accessTokenToAuthHolderRefs) {
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId]
            val authHolder = context.authHolderRepository.getById(newAuthHolderId)!!
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in context.maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId]!!
            val refreshToken = context.tokenRepository.getRefreshTokenById(newRefreshTokenId)
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.refreshToken = refreshToken
            context.tokenRepository.saveAccessToken(accessToken)
        }

        for ((oldGrantId, oldAccessTokenIds) in context.maps.grantToAccessTokensRefs) {
            val newGrantId = context.maps.grantOldToNewIdMap[oldGrantId]!!
            val site = context.approvedSiteRepository.getById(newGrantId)!!

            for (oldTokenId in oldAccessTokenIds) {
                val newTokenId = checkNotNull(context.maps.accessTokenOldToNewIdMap[oldTokenId]) { "missing map for old token $oldTokenId" }
                val token = context.tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                context.tokenRepository.saveAccessToken(token)
            }

            context.approvedSiteRepository.save(site)
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService_1_1::class.java)
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_1
    }
}
