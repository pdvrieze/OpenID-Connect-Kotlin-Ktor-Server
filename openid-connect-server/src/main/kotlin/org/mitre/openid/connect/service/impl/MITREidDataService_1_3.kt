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
import org.mitre.oauth2.model.PKCEAlgorithm
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
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.JsonUtils.readMap
import org.mitre.util.JsonUtils.readSet
import org.mitre.util.JsonUtils.writeNullSafeArray
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
 * Data service to import and export MITREid 1.3 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_3 : MITREidDataServiceSupport(), MITREidDataService {
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
        // version tag at the root

        writer.name(THIS_VERSION)

        writer.beginObject()

        // clients list
        writer.name(MITREidDataService.CLIENTS)
        writer.beginArray()
        writeClients(writer)
        writer.endArray()

        writer.name(MITREidDataService.GRANTS)
        writer.beginArray()
        writeGrants(writer)
        writer.endArray()

        writer.name(MITREidDataService.WHITELISTEDSITES)
        writer.beginArray()
        writeWhitelistedSites(writer)
        writer.endArray()

        writer.name(MITREidDataService.BLACKLISTEDSITES)
        writer.beginArray()
        writeBlacklistedSites(writer)
        writer.endArray()

        writer.name(MITREidDataService.AUTHENTICATIONHOLDERS)
        writer.beginArray()
        writeAuthenticationHolders(writer)
        writer.endArray()

        writer.name(MITREidDataService.ACCESSTOKENS)
        writer.beginArray()
        writeAccessTokens(writer)
        writer.endArray()

        writer.name(MITREidDataService.REFRESHTOKENS)
        writer.beginArray()
        writeRefreshTokens(writer)
        writer.endArray()

        writer.name(MITREidDataService.SYSTEMSCOPES)
        writer.beginArray()
        writeSystemScopes(writer)
        writer.endArray()

        for (extension in extensions) {
            if (extension.supportsVersion(THIS_VERSION)) {
                extension.exportExtensionData(writer)
                break
            }
        }

        writer.endObject() // end mitreid-connect-1.3
    }


    @Throws(IOException::class)
    private fun writeRefreshTokens(writer: JsonWriter) {
        for (token in tokenRepository.allRefreshTokens) {
            writer.beginObject()
            writer.name(ID).value(token.id)
            writer.name(EXPIRATION).value(toUTCString(token.expiration))
            writer.name(CLIENT_ID).value(token.client?.clientId)
            writer.name(AUTHENTICATION_HOLDER_ID).value(token.authenticationHolder!!.id)
            writer.name(VALUE).value(token.value)
            writer.endObject()
            logger.debug("Wrote refresh token {}", token.id)
        }
        logger.info("Done writing refresh tokens")
    }


    @Throws(IOException::class)
    private fun writeAccessTokens(writer: JsonWriter) {
        for (token in tokenRepository.allAccessTokens) {
            writer.beginObject()
            writer.name(ID).value(token.id)
            writer.name(EXPIRATION).value(toUTCString(token.expiration))
            writer.name(CLIENT_ID).value(token.client?.clientId)
            writer.name(AUTHENTICATION_HOLDER_ID).value(token.authenticationHolder.id)
            writer.name(REFRESH_TOKEN_ID)
                .value(if ((token.refreshToken != null)) token.refreshToken!!.id else null)
            writer.name(SCOPE)
            writer.beginArray()
            for (s in token.scope!!) {
                writer.value(s)
            }
            writer.endArray()
            writer.name(TYPE).value(token.tokenType)
            writer.name(VALUE).value(token.value)
            writer.endObject()
            logger.debug("Wrote access token {}", token.id)
        }
        logger.info("Done writing access tokens")
    }


    @Throws(IOException::class)
    private fun writeAuthenticationHolders(writer: JsonWriter) {
        for (holder in authHolderRepository.all) {
            writer.beginObject()
            writer.name(ID).value(holder.id)

            writer.name(REQUEST_PARAMETERS)
            writer.beginObject()
            for ((key, value) in holder.requestParameters ?: emptyMap()) {
                writer.name(key).value(value)
            }
            writer.endObject()
            writer.name(CLIENT_ID).value(holder.clientId)
            val scope = holder.scope
            writer.name(SCOPE)
            writer.beginArray()
            for (s in scope!!) {
                writer.value(s)
            }
            writer.endArray()
            writer.name(RESOURCE_IDS)
            writer.beginArray()
            if (holder.resourceIds != null) {
                for (s in holder.resourceIds!!) {
                    writer.value(s)
                }
            }
            writer.endArray()
            writer.name(AUTHORITIES)
            writer.beginArray()
            for (authority in holder.authorities!!) {
                writer.value(authority.authority)
            }
            writer.endArray()
            writer.name(APPROVED).value(holder.isApproved)
            writer.name(REDIRECT_URI).value(holder.redirectUri)
            writer.name(RESPONSE_TYPES)
            writer.beginArray()
            for (s in holder.responseTypes!!) {
                writer.value(s)
            }
            writer.endArray()
            writer.name(EXTENSIONS)
            writer.beginObject()
            for (entry in holder.extensions!!.entries) {
                // while the extension map itself is Serializable, we enforce storage of Strings
                if (entry.value is String) {
                    writer.name(entry.key).value(entry.value as String)
                } else {
                    logger.warn("Skipping non-string extension: $entry")
                }
            }
            writer.endObject()

            writer.name(SAVED_USER_AUTHENTICATION)
            if (holder.userAuth != null) {
                writer.beginObject()
                writer.name(NAME).value(holder.userAuth!!.name)
                writer.name(SOURCE_CLASS).value(holder.userAuth!!.sourceClass)
                writer.name(AUTHENTICATED).value(holder.userAuth!!.isAuthenticated)
                writer.name(AUTHORITIES)
                writer.beginArray()
                for (authority in holder.userAuth!!.authorities!!) {
                    writer.value(authority.authority)
                }
                writer.endArray()

                writer.endObject()
            } else {
                writer.nullValue()
            }


            writer.endObject()
            logger.debug("Wrote authentication holder {}", holder.id)
        }
        logger.info("Done writing authentication holders")
    }


    @Throws(IOException::class)
    private fun writeGrants(writer: JsonWriter) {
        for (site in approvedSiteRepository.all!!) {
            writer.beginObject()
            writer.name(ID).value(site.id)
            writer.name(ACCESS_DATE).value(toUTCString(site.accessDate))
            writer.name(CLIENT_ID).value(site.clientId)
            writer.name(CREATION_DATE).value(toUTCString(site.creationDate))
            writer.name(TIMEOUT_DATE).value(toUTCString(site.timeoutDate))
            writer.name(USER_ID).value(site.userId)
            writer.name(ALLOWED_SCOPES)
            writeNullSafeArray(writer, site.allowedScopes)
            val tokens = tokenRepository.getAccessTokensForApprovedSite(site)
            writer.name(APPROVED_ACCESS_TOKENS)
            writer.beginArray()
            for (token in tokens) {
                writer.value(token.id)
            }
            writer.endArray()
            writer.endObject()
            logger.debug("Wrote grant {}", site.id)
        }
        logger.info("Done writing grants")
    }


    @Throws(IOException::class)
    private fun writeWhitelistedSites(writer: JsonWriter) {
        for (wlSite in wlSiteRepository.all!!) {
            writer.beginObject()
            writer.name(ID).value(wlSite.id)
            writer.name(CLIENT_ID).value(wlSite.clientId)
            writer.name(CREATOR_USER_ID).value(wlSite.creatorUserId)
            writer.name(ALLOWED_SCOPES)
            writeNullSafeArray(writer, wlSite.allowedScopes)
            writer.endObject()
            logger.debug("Wrote whitelisted site {}", wlSite.id)
        }
        logger.info("Done writing whitelisted sites")
    }


    @Throws(IOException::class)
    private fun writeBlacklistedSites(writer: JsonWriter) {
        for (blSite in blSiteRepository.all) {
            writer.beginObject()
            writer.name(ID).value(blSite.id)
            writer.name(URI).value(blSite.uri)
            writer.endObject()
            logger.debug("Wrote blacklisted site {}", blSite.id)
        }
        logger.info("Done writing blacklisted sites")
    }


    private fun writeClients(writer: JsonWriter) {
        for (client in clientRepository.allClients) {
            try {
                writer.beginObject()
                writer.name(CLIENT_ID).value(client.clientId)
                writer.name(RESOURCE_IDS)
                writeNullSafeArray(writer, client.resourceIds)

                writer.name(SECRET).value(client.clientSecret)

                writer.name(SCOPE)
                writeNullSafeArray(writer, client.scope)

                writer.name(AUTHORITIES)
                writer.beginArray()
                for (authority in client.authorities) {
                    writer.value(authority.authority)
                }
                writer.endArray()
                writer.name(ACCESS_TOKEN_VALIDITY_SECONDS).value(client.accessTokenValiditySeconds)
                writer.name(REFRESH_TOKEN_VALIDITY_SECONDS).value(client.refreshTokenValiditySeconds)
                writer.name(ID_TOKEN_VALIDITY_SECONDS).value(client.idTokenValiditySeconds)
                writer.name(DEVICE_CODE_VALIDITY_SECONDS).value(client.deviceCodeValiditySeconds)
                writer.name(REDIRECT_URIS)
                writeNullSafeArray(writer, client.redirectUris)
                writer.name(CLAIMS_REDIRECT_URIS)
                writeNullSafeArray(writer, client.claimsRedirectUris)
                writer.name(NAME).value(client.clientName)
                writer.name(URI).value(client.clientUri)
                writer.name(LOGO_URI).value(client.logoUri)
                writer.name(CONTACTS)
                writeNullSafeArray(writer, client.contacts)
                writer.name(TOS_URI).value(client.tosUri)
                writer.name(TOKEN_ENDPOINT_AUTH_METHOD)
                    .value(if ((client.tokenEndpointAuthMethod != null)) client.tokenEndpointAuthMethod!!.value else null)
                writer.name(GRANT_TYPES)
                writer.beginArray()
                for (s in client.grantTypes) {
                    writer.value(s)
                }
                writer.endArray()
                writer.name(RESPONSE_TYPES)
                writer.beginArray()
                for (s in client.responseTypes) {
                    writer.value(s)
                }
                writer.endArray()
                writer.name(POLICY_URI).value(client.policyUri)
                writer.name(JWKS_URI).value(client.jwksUri)
                writer.name(JWKS).value(if ((client.jwks != null)) client.jwks.toString() else null)
                writer.name(APPLICATION_TYPE)
                    .value(if ((client.applicationType != null)) client.applicationType!!.value else null)
                writer.name(SECTOR_IDENTIFIER_URI).value(client.sectorIdentifierUri)
                writer.name(SUBJECT_TYPE)
                    .value(if ((client.subjectType != null)) client.subjectType!!.value else null)
                writer.name(REQUEST_OBJECT_SIGNING_ALG)
                    .value(if ((client.requestObjectSigningAlg != null)) client.requestObjectSigningAlg!!.name else null)
                writer.name(ID_TOKEN_SIGNED_RESPONSE_ALG)
                    .value(if ((client.idTokenSignedResponseAlg != null)) client.idTokenSignedResponseAlg!!.name else null)
                writer.name(ID_TOKEN_ENCRYPTED_RESPONSE_ALG)
                    .value(if ((client.idTokenEncryptedResponseAlg != null)) client.idTokenEncryptedResponseAlg!!.name else null)
                writer.name(ID_TOKEN_ENCRYPTED_RESPONSE_ENC)
                    .value(if ((client.idTokenEncryptedResponseEnc != null)) client.idTokenEncryptedResponseEnc!!.name else null)
                writer.name(USER_INFO_SIGNED_RESPONSE_ALG)
                    .value(if ((client.userInfoSignedResponseAlg != null)) client.userInfoSignedResponseAlg!!.name else null)
                writer.name(USER_INFO_ENCRYPTED_RESPONSE_ALG)
                    .value(if ((client.userInfoEncryptedResponseAlg != null)) client.userInfoEncryptedResponseAlg!!.name else null)
                writer.name(USER_INFO_ENCRYPTED_RESPONSE_ENC)
                    .value(if ((client.userInfoEncryptedResponseEnc != null)) client.userInfoEncryptedResponseEnc!!.name else null)
                writer.name(TOKEN_ENDPOINT_AUTH_SIGNING_ALG)
                    .value(if ((client.tokenEndpointAuthSigningAlg != null)) client.tokenEndpointAuthSigningAlg!!.name else null)
                writer.name(DEFAULT_MAX_AGE).value(client.defaultMaxAge)
                var requireAuthTime: Boolean? = null
                try {
                    requireAuthTime = client.requireAuthTime
                } catch (e: NullPointerException) {
                }
                if (requireAuthTime != null) {
                    writer.name(REQUIRE_AUTH_TIME).value(requireAuthTime)
                }
                writer.name(DEFAULT_ACR_VALUES)
                writeNullSafeArray(writer, client.defaultACRvalues)
                writer.name(INTITATE_LOGIN_URI).value(client.initiateLoginUri)
                writer.name(POST_LOGOUT_REDIRECT_URI)
                writeNullSafeArray(writer, client.postLogoutRedirectUris)
                writer.name(REQUEST_URIS)
                writeNullSafeArray(writer, client.requestUris)
                writer.name(DESCRIPTION).value(client.clientDescription)
                writer.name(ALLOW_INTROSPECTION).value(client.isAllowIntrospection)
                writer.name(REUSE_REFRESH_TOKEN).value(client.isReuseRefreshToken)
                writer.name(CLEAR_ACCESS_TOKENS_ON_REFRESH).value(client.isClearAccessTokensOnRefresh)
                writer.name(DYNAMICALLY_REGISTERED).value(client.isDynamicallyRegistered)
                writer.name(CODE_CHALLENGE_METHOD)
                    .value(if (client.codeChallengeMethod != null) client.codeChallengeMethod!!.name else null)
                writer.name(SOFTWARE_ID).value(client.softwareId)
                writer.name(SOFTWARE_VERSION).value(client.softwareVersion)
                writer.name(SOFTWARE_STATEMENT)
                    .value(if (client.softwareStatement != null) client.softwareStatement!!.serialize() else null)
                writer.name(CREATION_DATE).value(toUTCString(client.createdAt))
                writer.endObject()
                logger.debug("Wrote client {}", client.id)
            } catch (ex: IOException) {
                logger.error("Unable to write client {}", client.id, ex)
            }
        }
        logger.info("Done writing clients")
    }


    private fun writeSystemScopes(writer: JsonWriter) {
        for (sysScope in sysScopeRepository.all) {
            try {
                writer.beginObject()
                writer.name(ID).value(sysScope.id)
                writer.name(DESCRIPTION).value(sysScope.description)
                writer.name(ICON).value(sysScope.icon)
                writer.name(VALUE).value(sysScope.value)
                writer.name(RESTRICTED).value(sysScope.isRestricted)
                writer.name(DEFAULT_SCOPE).value(sysScope.isDefaultScope)
                writer.endObject()
                logger.debug("Wrote system scope {}", sysScope.id)
            } catch (ex: IOException) {
                logger.error("Unable to write system scope {}", sysScope.id, ex)
            }
        }
        logger.info("Done writing system scopes")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataService#importData(com.google.gson.stream.JsonReader)
	 */
    @Throws(IOException::class)
    override fun importData(reader: JsonReader) {
        logger.info("Reading configuration for 1.3")

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
                        var processed = false
                        for (extension in extensions) {
                            if (extension.supportsVersion(THIS_VERSION)) {
                                processed = extension.importExtensionData(name, reader)
                                if (processed) {
                                    // if the extension processed data, break out of this inner loop
                                    // (only the first extension to claim an extension point gets it)
                                    break
                                }
                            }
                        }
                        if (!processed) {
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
        fixObjectReferences()
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
            val newId = tokenRepository.saveRefreshToken(token).id
            maps.refreshTokenToClientRefs[currentId!!] = clientId!!
            maps.refreshTokenToAuthHolderRefs[currentId] = authHolderId!!
            maps.refreshTokenOldToNewIdMap[currentId] = newId!!
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
            reader.endObject()
            val newId = tokenRepository.saveAccessToken(token).id
            maps.accessTokenToClientRefs[currentId!!] = clientId!!
            maps.accessTokenToAuthHolderRefs[currentId] = authHolderId!!
            if (refreshTokenId != null) {
                maps.accessTokenToRefreshTokenRefs[currentId] = refreshTokenId
            }
            maps.accessTokenOldToNewIdMap[currentId] = newId!!
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
            val newId = approvedSiteRepository.save(site).id
            maps.grantOldToNewIdMap[currentId!!] = newId!!
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
                            name == RESOURCE_IDS -> client.resourceIds = readSet(reader)
                            name == SECRET -> client.clientSecret = reader.nextString()
                            name == SCOPE -> client.setScope(readSet(reader))

                            name == AUTHORITIES -> client.authorities =
                                readSet<String>(reader).mapTo(HashSet(), ::SimpleGrantedAuthority)

                            name == ACCESS_TOKEN_VALIDITY_SECONDS ->
                                client.accessTokenValiditySeconds = reader.nextInt()

                            name == REFRESH_TOKEN_VALIDITY_SECONDS ->
                                client.refreshTokenValiditySeconds = reader.nextInt()

                            name == ID_TOKEN_VALIDITY_SECONDS ->
                                client.idTokenValiditySeconds = reader.nextInt()

                            name == DEVICE_CODE_VALIDITY_SECONDS ->
                                client.deviceCodeValiditySeconds = reader.nextInt()

                            name == REDIRECT_URIS -> client.redirectUris = readSet(reader)
                            name == CLAIMS_REDIRECT_URIS -> client.claimsRedirectUris = readSet(reader)
                            name == NAME -> client.clientName = reader.nextString()
                            name == URI -> client.clientUri = reader.nextString()
                            name == LOGO_URI -> client.logoUri = reader.nextString()
                            name == CONTACTS -> client.contacts = readSet(reader)
                            name == TOS_URI -> client.tosUri = reader.nextString()

                            name == TOKEN_ENDPOINT_AUTH_METHOD ->
                                client.tokenEndpointAuthMethod = AuthMethod.getByValue(reader.nextString())

                            name == GRANT_TYPES ->
                                client.grantTypes = readSet<String>(reader).toHashSet()

                            name == RESPONSE_TYPES ->
                                client.responseTypes = readSet<String>(reader).toHashSet()

                            name == POLICY_URI -> client.policyUri = reader.nextString()

                            name == APPLICATION_TYPE ->
                                client.applicationType = AppType.valueOf(reader.nextString())

                            name == SECTOR_IDENTIFIER_URI -> client.sectorIdentifierUri = reader.nextString()

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
                            name == POST_LOGOUT_REDIRECT_URI -> client.postLogoutRedirectUris = readSet(reader)
                            name == REQUEST_URIS -> client.requestUris = readSet(reader)
                            name == DESCRIPTION -> client.clientDescription = reader.nextString()
                            name == ALLOW_INTROSPECTION -> client.isAllowIntrospection = reader.nextBoolean()
                            name == REUSE_REFRESH_TOKEN -> client.isReuseRefreshToken = reader.nextBoolean()

                            name == CLEAR_ACCESS_TOKENS_ON_REFRESH ->
                                client.isClearAccessTokensOnRefresh = reader.nextBoolean()

                            name == DYNAMICALLY_REGISTERED ->
                                client.isDynamicallyRegistered = reader.nextBoolean()

                            name == CODE_CHALLENGE_METHOD ->
                                client.codeChallengeMethod = PKCEAlgorithm.parse(reader.nextString())

                            name == SOFTWARE_ID -> client.softwareId = reader.nextString()
                            name == SOFTWARE_VERSION -> client.softwareVersion = reader.nextString()

                            name == SOFTWARE_STATEMENT -> {
                                try {
                                    client.softwareStatement = JWTParser.parse(reader.nextString())
                                } catch (e: ParseException) {
                                    logger.error("Couldn't parse software statement", e)
                                }
                            }

                            name == CREATION_DATE ->
                                client.createdAt = utcToDate(reader.nextString())

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

    private fun fixObjectReferences() {
        logger.info("Fixing object references...")
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
            val newAuthHolderId = maps.authHolderOldToNewIdMap[oldAuthHolderId] ?: error("No autholder old->new for $oldAuthHolderId")
            val authHolder = authHolderRepository.getById(newAuthHolderId) ?: error("No authHolder with id $newAuthHolderId found")
            val newAccessTokenId = maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = maps.refreshTokenOldToNewIdMap[oldRefreshTokenId] ?: error("No refresh old->new for $oldRefreshTokenId")
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
                val newTokenId = maps.accessTokenOldToNewIdMap[oldTokenId] ?: error("No access old->new map for $oldTokenId")
                val token = tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                tokenRepository.saveAccessToken(token)
            }

            approvedSiteRepository.save(site)
        }
        /*
		refreshTokenToClientRefs.clear();
		refreshTokenToAuthHolderRefs.clear();
		accessTokenToClientRefs.clear();
		accessTokenToAuthHolderRefs.clear();
		accessTokenToRefreshTokenRefs.clear();
		refreshTokenOldToNewIdMap.clear();
		accessTokenOldToNewIdMap.clear();
		grantOldToNewIdMap.clear();
		 */
        logger.info("Done fixing object references.")
    }

    companion object {
        private const val DEFAULT_SCOPE = "defaultScope"
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
        private const val ID_TOKEN_VALIDITY_SECONDS = "idTokenValiditySeconds"
        private const val DEVICE_CODE_VALIDITY_SECONDS = "deviceCodeValiditySeconds"
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
        private const val CODE_CHALLENGE_METHOD = "codeChallengeMethod"
        private const val SOFTWARE_STATEMENT = "softwareStatement"
        private const val SOFTWARE_VERSION = "softwareVersion"
        private const val SOFTWARE_ID = "softwareId"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService_1_3::class.java)
        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_3
    }
}
