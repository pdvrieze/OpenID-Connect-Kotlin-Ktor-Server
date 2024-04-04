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

import com.google.gson.stream.JsonWriter
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.repository.ApprovedSiteRepository
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.toUTCString
import org.mitre.openid.connect.service.MITREidDataService.Companion.warnIgnored
import org.mitre.openid.connect.service.MITREidDataService.Context
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.util.JsonUtils.writeNullSafeArray
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.io.IOException

/**
 *
 * Data service to import and export MITREid 1.3 configuration.
 *
 * @author jricher
 * @author arielak
 */
@Service
class MITREidDataService_1_3 : MITREidDataService {
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
            writer.name(AUTHENTICATION_HOLDER_ID).value(token.authenticationHolder.id)
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
                writer.name(APPLICATION_TYPE).value(client.applicationType.value)
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
                } catch (_: NullPointerException) {
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


    override fun importData(config: MITREidDataService.ExtendedConfiguration) {
        val context = Context(clientRepository, approvedSiteRepository, wlSiteRepository, blSiteRepository, authHolderRepository, tokenRepository, sysScopeRepository, extensions, maps)
        context.importData(config)
    }

    override fun importData(configJson: String) {
        val conf = MITREidDataService.json.decodeFromString<MITREidDataService.ExtendedConfiguration12>(configJson)
        importData(conf)
    }

    override fun importGrant(context: Context, delegate: ApprovedSite.SerialDelegate) {
        with(delegate) {
            whitelistedSiteId = whitelistedSiteId.warnIgnored("whitelistedSiteId")
        }
        super.importGrant(context, delegate)
    }

    override fun fixObjectReferences(context: Context) {
        logger.info("Fixing object references...")
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
        for ((oldAccessTokenId, oldAuthHolderId) in context.maps.accessTokenToAuthHolderRefs) {
            val newAuthHolderId = context.maps.authHolderOldToNewIdMap[oldAuthHolderId] ?: error("No autholder old->new for $oldAuthHolderId")
            val authHolder = context.authHolderRepository.getById(newAuthHolderId) ?: error("No authHolder with id $newAuthHolderId found")
            val newAccessTokenId = context.maps.accessTokenOldToNewIdMap[oldAccessTokenId]!!
            val accessToken = context.tokenRepository.getAccessTokenById(newAccessTokenId)!!
            accessToken.authenticationHolder = authHolder
            context.tokenRepository.saveAccessToken(accessToken)
        }
        for ((oldAccessTokenId, oldRefreshTokenId) in context.maps.accessTokenToRefreshTokenRefs) {
            val newRefreshTokenId = context.maps.refreshTokenOldToNewIdMap[oldRefreshTokenId] ?: error("No refresh old->new for $oldRefreshTokenId")
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
                val newTokenId = context.maps.accessTokenOldToNewIdMap[oldTokenId] ?: error("No access old->new map for $oldTokenId")
                val token = context.tokenRepository.getAccessTokenById(newTokenId)!!
                token.approvedSite = site
                context.tokenRepository.saveAccessToken(token)
            }

            context.approvedSiteRepository.save(site)
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
