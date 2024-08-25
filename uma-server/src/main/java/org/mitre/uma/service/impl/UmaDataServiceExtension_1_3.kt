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
package org.mitre.uma.service.impl

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.json.*
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.util.requireId
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataService.Companion.toUTCString
import org.mitre.openid.connect.service.MITREidDataService.Companion.utcToDate
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.uma.model.Claim
import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.util.asString
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.io.IOException

/**
 * @author jricher
 */
@Service("umaDataExtension_1_3")
class UmaDataServiceExtension_1_3 : MITREidDataServiceExtension {
    @Autowired
    private lateinit var registeredClientService: SavedRegisteredClientService

    @Autowired
    private lateinit var resourceSetRepository: ResourceSetRepository

    @Autowired
    private lateinit var permissionRepository: PermissionRepository

    @Autowired
    private lateinit var tokenRepository: OAuth2TokenRepository

    private val tokenToPermissionRefs: MutableMap<Long, Set<Long>> = HashMap()

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#supportsVersion(java.lang.String)
	 */
    override fun supportsVersion(version: String): Boolean {
        return THIS_VERSION == version
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#exportExtensionData(com.google.gson.stream.JsonWriter)
	 */
    @Throws(IOException::class)
    override fun exportExtensionData(): JsonObject {
        return buildJsonObject {
            putJsonArray(SAVED_REGISTERED_CLIENTS) {
                writeSavedRegisteredClients(this)
            }

            putJsonArray(RESOURCE_SETS) {
                writeResourceSets(this)
            }

            putJsonArray(PERMISSION_TICKETS) {
                writePermissionTickets(this)
            }

            putJsonArray(TOKEN_PERMISSIONS) {
                writeTokenPermissions(this)
            }
        }
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writeTokenPermissions(builder: JsonArrayBuilder) {
        for (token in tokenRepository.allAccessTokens) {
            if (token.permissions!!.isNotEmpty()) { // skip tokens that don't have the permissions structure attached
                builder.addJsonObject {
                    put(TOKEN_ID, token.id)
                    putJsonArray(PERMISSIONS) {
                        for (perm in token.permissions!!) {
                            addJsonObject {
                                put(RESOURCE_SET, perm.resourceSet!!.id)
                                putJsonArray(SCOPES) {
                                    addAll(perm.scopes)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writePermissionTickets(builder: JsonArrayBuilder) {
        for (ticket in permissionRepository.all!!) {
            builder.addJsonObject {
                putJsonArray(CLAIMS_SUPPLIED) {
                    for(claim in ticket.claimsSupplied!!) {
                        addJsonObject {
                            putJsonArray(ISSUER) {
                                addAll(claim.issuer)
                            }
                            putJsonArray(CLAIM_TOKEN_FORMAT) {
                                addAll(claim.claimTokenFormat)
                            }
                            put(CLAIM_TYPE, claim.claimType)
                            put(FRIENDLY_NAME, claim.friendlyName)
                            put(NAME, claim.name)
                            claim.value?.let { put(VALUE, it) }
                        }
                    }
                }

                put(EXPIRATION, toUTCString(ticket?.expiration))
                putJsonObject(PERMISSION) {
                    val perm = ticket.permission
                    put(RESOURCE_SET, perm.resourceSet!!.id)
                    putJsonArray(SCOPES) {
                        addAll(perm.scopes)
                    }
                }
                put(TICKET, ticket.ticket)
            }
        }
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writeResourceSets(builder: JsonArrayBuilder) {
        for (rs in resourceSetRepository.all) {
            builder.addJsonObject {
                put(ID, rs.id)
                put(CLIENT_ID, rs.clientId)
                put(ICON_URI, rs.iconUri)
                put(NAME, rs.name)
                put(TYPE, rs.type)
                put(URI, rs.uri)
                put(OWNER, rs.owner)
                putJsonArray(POLICIES) {
                    for(policy in rs.policies) {
                        addJsonObject {
                            put(NAME, policy.name)
                            putJsonArray(SCOPES) { addAll(policy.scopes) }
                            putJsonArray(CLAIMS_REQUIRED) {
                                for (claim in policy.claimsRequired!!) {
                                    addJsonObject {
                                        putJsonArray(ISSUER) { addAll(claim.issuer) }
                                        putJsonArray(CLAIM_TOKEN_FORMAT) { addAll(claim.claimTokenFormat) }
                                        put(CLAIM_TYPE, claim.claimType)
                                        put(FRIENDLY_NAME, claim.friendlyName)
                                        put(NAME, claim.name)
                                        claim.value?.let { put(VALUE, it) }
                                    }
                                }
                            }
                        }
                    }
                }
                putJsonArray(SCOPES) { addAll(rs.scopes) }
            }
            logger.debug("Finished writing resource set {}", rs.id)
        }
    }


    @Throws(IOException::class)
    private fun writeSavedRegisteredClients(builder: JsonArrayBuilder) {
        for (src in registeredClientService.all) {
            builder.addJsonObject {
                put(ISSUER, src.issuer)
                src.registeredClient!!.source?.let { put(REGISTERED_CLIENT, it) }
            }
            logger.debug("Wrote saved registered client {}", src.id)
        }
        logger.info("Done writing saved registered clients")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#importExtensionData(com.google.gson.stream.JsonReader)
	 */
    @Throws(IOException::class)
    override fun importExtensionData(name: String?, data: JsonElement): Boolean {
        if (name == SAVED_REGISTERED_CLIENTS) {
            readSavedRegisteredClients(data)
            return true
        } else if (name == RESOURCE_SETS) {
            readResourceSets(data)
            return true
        } else if (name == PERMISSION_TICKETS) {
            readPermissionTickets(data)
            return true
        } else if (name == TOKEN_PERMISSIONS) {
            readTokenPermissions(data)
            return true
        } else {
            return false
        }
    }


    @Throws(IOException::class)
    private fun readTokenPermissions(data: JsonElement) {
        check(data is JsonArray)
        for(o in data) {
            require(o is JsonObject)
            val tokenId: Long = requireNotNull(o[TOKEN_ID]).jsonPrimitive.long
            val permissions: Set<Long> = requireNotNull(o[PERMISSIONS]).jsonArray.mapTo(HashSet()) { permObj ->
                require(permObj is JsonObject)
                val rsId = requireNotNull(permObj[RESOURCE_SET]).jsonPrimitive.long
                val scope = (permObj[SCOPES] as JsonArray).mapTo(HashSet()) { it.asString() }
                val saved = permissionRepository.saveRawPermission(Permission(scopes = scope))
                permissionToResourceRefs[saved.id!!] = rsId
                saved.id!!
            }
            tokenToPermissionRefs[tokenId] = permissions
        }
    }

    private val permissionToResourceRefs: MutableMap<Long, Long> = HashMap()


    @Throws(IOException::class)
    private fun readPermissionTickets(reader: JsonElement) {
        require(reader is JsonArray)

        for(ticketObj in reader) {
            require(ticketObj is JsonObject)
            val ticketExpiration = ticketObj[EXPIRATION]?.let { utcToDate(it.asString()) }
            val ticketString = ticketObj[TICKET]?.let { it.asString() }
            val permission = requireNotNull(ticketObj[PERMISSIONS]).jsonObject.let { p ->
                val scopes = requireNotNull(p[SCOPES]).jsonArray.mapTo(HashSet()) { it.asString() }
                val rsId = requireNotNull(p[RESOURCE_SET]).jsonPrimitive.long
                val savedPerm = permissionRepository.saveRawPermission(Permission(scopes = scopes))
                permissionToResourceRefs[savedPerm.id!!] = rsId
                savedPerm
            }
            val claimsSupplied = ticketObj[CLAIMS_SUPPLIED]?.let {
                Json.decodeFromJsonElement(SetSerializer(Claim.serializer()), it)
            }
            val ticket = PermissionTicket(
                permission = permission,
                ticket = ticketString,
                expiration = ticketExpiration,
                claimsSupplied = claimsSupplied
            )
            permissionRepository.save(ticket)
        }
    }


    private val resourceSetOldToNewIdMap: MutableMap<Long?, Long?> = HashMap()


    @Throws(IOException::class)
    private fun readResourceSets(reader: JsonElement) {
        require(reader is JsonArray)
        for(e in reader) {
            val rawRS = json.decodeFromJsonElement<ResourceSet>(e)
            val oldId = rawRS.id
            val newId = resourceSetRepository.save(rawRS).id

            if (oldId!=null) {
                resourceSetOldToNewIdMap[oldId] = newId
            }
        }
    }


    @Throws(IOException::class)
    private fun readSavedRegisteredClients(data: JsonElement) {
        require(data is JsonArray)
        for (o in data) {
            require(o is JsonObject)
            val issuer = requireNotNull(o[ISSUER]).asString()
            val client = json.decodeFromString<RegisteredClient>(requireNotNull(o[REGISTERED_CLIENT]).asString())
            registeredClientService.save(issuer, client)
            logger.debug("Saved registered client")
        }
        logger.info("Done reading saved registered clients")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#fixExtensionObjectReferences()
	 */
    override fun fixExtensionObjectReferences(maps: MITREidDataServiceMaps) {
        for (permissionId in permissionToResourceRefs.keys) {
            val oldResourceId = permissionToResourceRefs[permissionId]
            val newResourceId = resourceSetOldToNewIdMap[oldResourceId].requireId()
            val p = permissionRepository.getById(permissionId)!!
            val rs = resourceSetRepository.getById(newResourceId)!!
            p.resourceSet = rs
            permissionRepository.saveRawPermission(p)
            logger.debug("Mapping rsid $oldResourceId to $newResourceId for permission $permissionId")
        }
        for (tokenId in tokenToPermissionRefs.keys) {
            val newTokenId = maps.accessTokenOldToNewIdMap[tokenId].requireId()
            val token = tokenRepository.getAccessTokenById(newTokenId)!!

            val permissions: MutableSet<Permission> = HashSet()
            for (permissionId in tokenToPermissionRefs[tokenId]!!) {
                val p = permissionRepository.getById(permissionId)!!
                permissions.add(p)
            }

            token.permissions = permissions
            tokenRepository.saveAccessToken(token)
        }
        permissionToResourceRefs.clear()
        resourceSetOldToNewIdMap.clear()
        tokenToPermissionRefs.clear()
    }

    companion object {

        internal val json = Json { ignoreUnknownKeys = true }

        private const val THIS_VERSION = MITREidDataService.MITREID_CONNECT_1_3

        private const val REGISTERED_CLIENT = "registeredClient"
        private const val URI = "uri"
        private const val NAME = "name"
        private const val TYPE = "type"
        private const val VALUE = "value"
        private const val CLIENT_ID = "clientId"
        private const val EXPIRATION = "expiration"
        private const val ID = "id"
        private const val ICON_URI = "iconUri"
        private const val OWNER = "owner"
        private const val POLICIES = "policies"
        private const val SCOPES = "scopes"
        private const val CLAIMS_REQUIRED = "claimsRequired"
        private const val ISSUER = "issuer"
        private const val CLAIM_TOKEN_FORMAT = "claimTokenFormat"
        private const val CLAIM_TYPE = "claimType"
        private const val FRIENDLY_NAME = "friendlyName"
        private const val PERMISSIONS = "permissions"
        private const val RESOURCE_SET = "resourceSet"
        private const val PERMISSION_TICKETS = "permissionTickets"
        private const val PERMISSION = "permission"
        private const val TICKET = "ticket"
        private const val CLAIMS_SUPPLIED = "claimsSupplied"
        private const val SAVED_REGISTERED_CLIENTS = "savedRegisteredClients"
        private const val RESOURCE_SETS = "resourceSets"
        private const val TOKEN_PERMISSIONS = "tokenPermissions"
        private const val TOKEN_ID = "tokenId"

        private val logger: Logger = LoggerFactory.getLogger(UmaDataServiceExtension_1_3::class.java)
    }
}
