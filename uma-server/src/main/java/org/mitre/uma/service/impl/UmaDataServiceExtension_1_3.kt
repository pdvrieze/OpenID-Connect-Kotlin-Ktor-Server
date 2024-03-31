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

import com.google.gson.JsonParser
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.oauth2.util.toJavaId
import org.mitre.openid.connect.ClientDetailsEntityJsonProcessor.parseRegistered
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.MITREidDataServiceExtension
import org.mitre.openid.connect.service.MITREidDataServiceMaps
import org.mitre.openid.connect.service.impl.MITREidDataServiceSupport
import org.mitre.uma.model.Claim
import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.Policy
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.util.JsonUtils.readSet
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.io.IOException

/**
 * @author jricher
 */
@Service("umaDataExtension_1_3")
class UmaDataServiceExtension_1_3 : MITREidDataServiceSupport(), MITREidDataServiceExtension {
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
    override fun exportExtensionData(writer: JsonWriter?) {
        writer!!.name(SAVED_REGISTERED_CLIENTS)
        writer.beginArray()
        writeSavedRegisteredClients(writer)
        writer.endArray()

        writer.name(RESOURCE_SETS)
        writer.beginArray()
        writeResourceSets(writer)
        writer.endArray()

        writer.name(PERMISSION_TICKETS)
        writer.beginArray()
        writePermissionTickets(writer)
        writer.endArray()

        writer.name(TOKEN_PERMISSIONS)
        writer.beginArray()
        writeTokenPermissions(writer)
        writer.endArray()
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writeTokenPermissions(writer: JsonWriter?) {
        for (token in tokenRepository.allAccessTokens) {
            if (!token.permissions!!.isEmpty()) { // skip tokens that don't have the permissions structure attached
                writer!!.beginObject()
                writer.name(TOKEN_ID).value(token.id)
                writer.name(PERMISSIONS)
                writer.beginArray()
                for (p in token.permissions!!) {
                    writer.beginObject()
                    writer.name(RESOURCE_SET).value(p.resourceSet!!.id)
                    writer.name(SCOPES)
                    writer.beginArray()
                    for (s in p.scopes!!) {
                        writer.value(s)
                    }
                    writer.endArray()
                    writer.endObject()
                }
                writer.endArray()

                writer.endObject()
            }
        }
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writePermissionTickets(writer: JsonWriter?) {
        for (ticket in permissionRepository.all!!) {
            writer!!.beginObject()

            writer.name(CLAIMS_SUPPLIED)
            writer.beginArray()
            for (claim in ticket!!.claimsSupplied!!) {
                writer.beginObject()

                writer.name(ISSUER)
                writer.beginArray()
                for (issuer in claim.issuer!!) {
                    writer.value(issuer)
                }
                writer.endArray()
                writer.name(CLAIM_TOKEN_FORMAT)
                writer.beginArray()
                for (format in claim.claimTokenFormat!!) {
                    writer.value(format)
                }
                writer.endArray()
                writer.name(CLAIM_TYPE).value(claim.claimType)
                writer.name(FRIENDLY_NAME).value(claim.friendlyName)
                writer.name(NAME).value(claim.name)
                writer.name(VALUE).value(claim.value.toString())
                writer.endObject()
            }
            writer.endArray()

            writer.name(EXPIRATION).value(toUTCString(ticket.expiration))

            writer.name(PERMISSION)
            writer.beginObject()
            val p = ticket.permission
            writer.name(RESOURCE_SET).value(p!!.resourceSet!!.id)
            writer.name(SCOPES)
            writer.beginArray()
            for (s in p.scopes!!) {
                writer.value(s)
            }
            writer.endArray()
            writer.endObject()

            writer.name(TICKET).value(ticket.ticket)

            writer.endObject()
        }
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun writeResourceSets(writer: JsonWriter?) {
        for (rs in resourceSetRepository.all!!) {
            writer!!.beginObject()
            writer.name(ID).value(rs.id)
            writer.name(CLIENT_ID).value(rs.clientId)
            writer.name(ICON_URI).value(rs.iconUri)
            writer.name(NAME).value(rs.name)
            writer.name(TYPE).value(rs.type)
            writer.name(URI).value(rs.uri)
            writer.name(OWNER).value(rs.owner)
            writer.name(POLICIES)
            writer.beginArray()
            for (policy in rs.policies!!) {
                writer.beginObject()
                writer.name(NAME).value(policy.name)
                writer.name(SCOPES)
                writer.beginArray()
                for (scope in policy.scopes!!) {
                    writer.value(scope)
                }
                writer.endArray()
                writer.name(CLAIMS_REQUIRED)
                writer.beginArray()
                for (claim in policy.claimsRequired!!) {
                    writer.beginObject()

                    writer.name(ISSUER)
                    writer.beginArray()
                    for (issuer in claim.issuer!!) {
                        writer.value(issuer)
                    }
                    writer.endArray()
                    writer.name(CLAIM_TOKEN_FORMAT)
                    writer.beginArray()
                    for (format in claim.claimTokenFormat!!) {
                        writer.value(format)
                    }
                    writer.endArray()
                    writer.name(CLAIM_TYPE).value(claim.claimType)
                    writer.name(FRIENDLY_NAME).value(claim.friendlyName)
                    writer.name(NAME).value(claim.name)
                    writer.name(VALUE).value(claim.value.toString())
                    writer.endObject()
                }
                writer.endArray()
                writer.endObject()
            }
            writer.endArray()
            writer.name(SCOPES)
            writer.beginArray()
            for (scope in rs.scopes) {
                writer.value(scope)
            }
            writer.endArray()
            writer.endObject()
            logger.debug("Finished writing resource set {}", rs.id)
        }
    }


    @Throws(IOException::class)
    private fun writeSavedRegisteredClients(writer: JsonWriter?) {
        for (src in registeredClientService.all) {
            writer!!.beginObject()
            writer.name(ISSUER).value(src.issuer)
            writer.name(REGISTERED_CLIENT).value(src.registeredClient!!.source.toString())
            writer.endObject()
            logger.debug("Wrote saved registered client {}", src.id)
        }
        logger.info("Done writing saved registered clients")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#importExtensionData(com.google.gson.stream.JsonReader)
	 */
    @Throws(IOException::class)
    override fun importExtensionData(name: String?, reader: JsonReader): Boolean {
        if (name == SAVED_REGISTERED_CLIENTS) {
            readSavedRegisteredClients(reader)
            return true
        } else if (name == RESOURCE_SETS) {
            readResourceSets(reader)
            return true
        } else if (name == PERMISSION_TICKETS) {
            readPermissionTickets(reader)
            return true
        } else if (name == TOKEN_PERMISSIONS) {
            readTokenPermissions(reader)
            return true
        } else {
            return false
        }
    }


    @Throws(IOException::class)
    private fun readTokenPermissions(reader: JsonReader) {
        reader.beginArray()
        while (reader.hasNext()) {
            reader.beginObject()
            var tokenId: Long? = null
            val permissions: MutableSet<Long> = HashSet()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (name == TOKEN_ID) {
                            tokenId = reader.nextLong()
                        } else if (name == PERMISSIONS) {
                            reader.beginArray()
                            while (reader.hasNext()) {
                                val p = Permission()
                                var rsid: Long? = null
                                var scope: Set<String> = emptySet()
                                reader.beginObject()
                                while (reader.hasNext()) {
                                    when (reader.peek()) {
                                        JsonToken.END_OBJECT -> continue
                                        JsonToken.NAME -> {
                                            val pname = reader.nextName()
                                            if (reader.peek() == JsonToken.NULL) {
                                                reader.skipValue()
                                            } else if (pname == RESOURCE_SET) {
                                                rsid = reader.nextLong()
                                            } else if (pname == SCOPES) {
                                                scope = readSet<String>(reader)
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
                                checkNotNull(rsid)
                                p.scopes = scope
                                val saved = permissionRepository.saveRawPermission(p)
                                permissionToResourceRefs[saved.id!!] = rsid
                                permissions.add(saved.id!!)
                            }
                            reader.endArray()
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
            checkNotNull(tokenId)
            tokenToPermissionRefs[tokenId] = permissions
        }
        reader.endArray()
    }

    private val permissionToResourceRefs: MutableMap<Long, Long> = HashMap()


    @Throws(IOException::class)
    private fun readPermissionTickets(reader: JsonReader?) {
        val parser = JsonParser()
        reader!!.beginArray()
        while (reader.hasNext()) {
            val ticket = PermissionTicket()
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == CLAIMS_SUPPLIED) {
                            val claimsSupplied: MutableSet<Claim> = HashSet()
                            reader.beginArray()
                            while (reader.hasNext()) {
                                val c = Claim()
                                reader.beginObject()
                                while (reader.hasNext()) {
                                    when (reader.peek()) {
                                        JsonToken.END_OBJECT -> continue
                                        JsonToken.NAME -> {
                                            val cname = reader.nextName()
                                            if (reader.peek() == JsonToken.NULL) {
                                                reader.skipValue()
                                            } else if (cname == ISSUER) {
                                                c.issuer = readSet(reader)
                                            } else if (cname == CLAIM_TOKEN_FORMAT) {
                                                c.claimTokenFormat = readSet(reader)
                                            } else if (cname == CLAIM_TYPE) {
                                                c.claimType = reader.nextString()
                                            } else if (cname == FRIENDLY_NAME) {
                                                c.friendlyName = reader.nextString()
                                            } else if (cname == NAME) {
                                                c.name = reader.nextString()
                                            } else if (cname == VALUE) {
                                                val e = parser.parse(reader.nextString())
                                                c.value = e
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
                                claimsSupplied.add(c)
                            }
                            reader.endArray()
                            ticket.claimsSupplied = claimsSupplied
                        } else if (name == EXPIRATION) {
                            ticket.expiration = utcToDate(reader.nextString())
                        } else if (name == PERMISSION) {
                            val p = Permission()
                            var rsid: Long? = null
                            reader.beginObject()
                            while (reader.hasNext()) {
                                when (reader.peek()) {
                                    JsonToken.END_OBJECT -> continue
                                    JsonToken.NAME -> {
                                        val pname = reader.nextName()
                                        if (reader.peek() == JsonToken.NULL) {
                                            reader.skipValue()
                                        } else if (pname == RESOURCE_SET) {
                                            rsid = reader.nextLong()
                                        } else if (pname == SCOPES) {
                                            p.scopes = readSet(reader)
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
                            checkNotNull(rsid)
                            reader.endObject()
                            val saved = permissionRepository.saveRawPermission(p)
                            permissionToResourceRefs[saved.id!!] = rsid
                            ticket.permission = saved
                        } else if (name == TICKET) {
                            ticket.ticket = reader.nextString()
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
            permissionRepository.save(ticket)
        }
        reader.endArray()
    }


    private val resourceSetOldToNewIdMap: MutableMap<Long?, Long?> = HashMap()


    @Throws(IOException::class)
    private fun readResourceSets(reader: JsonReader?) {
        val parser = JsonParser()
        reader!!.beginArray()
        while (reader.hasNext()) {
            var oldId: Long? = null
            val rs = ResourceSet()
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ID) {
                            oldId = reader.nextLong()
                        } else if (name == CLIENT_ID) {
                            rs.clientId = reader.nextString()
                        } else if (name == ICON_URI) {
                            rs.iconUri = reader.nextString()
                        } else if (name == NAME) {
                            rs.name = reader.nextString()
                        } else if (name == TYPE) {
                            rs.type = reader.nextString()
                        } else if (name == URI) {
                            rs.uri = reader.nextString()
                        } else if (name == OWNER) {
                            rs.owner = reader.nextString()
                        } else if (name == POLICIES) {
                            val policies: MutableSet<Policy> = HashSet()
                            reader.beginArray()
                            while (reader.hasNext()) {
                                val p = Policy()
                                reader.beginObject()
                                while (reader.hasNext()) {
                                    when (reader.peek()) {
                                        JsonToken.END_OBJECT -> continue
                                        JsonToken.NAME -> {
                                            val pname = reader.nextName()
                                            if (reader.peek() == JsonToken.NULL) {
                                                reader.skipValue()
                                            } else if (pname == NAME) {
                                                p.name = reader.nextString()
                                            } else if (pname == SCOPES) {
                                                p.scopes = readSet(reader)
                                            } else if (pname == CLAIMS_REQUIRED) {
                                                val claimsRequired: MutableSet<Claim> = HashSet()
                                                reader.beginArray()
                                                while (reader.hasNext()) {
                                                    val c = Claim()
                                                    reader.beginObject()
                                                    while (reader.hasNext()) {
                                                        when (reader.peek()) {
                                                            JsonToken.END_OBJECT -> continue
                                                            JsonToken.NAME -> {
                                                                val cname = reader.nextName()
                                                                if (reader.peek() == JsonToken.NULL) {
                                                                    reader.skipValue()
                                                                } else if (cname == ISSUER) {
                                                                    c.issuer = readSet(reader)
                                                                } else if (cname == CLAIM_TOKEN_FORMAT) {
                                                                    c.claimTokenFormat = readSet(reader)
                                                                } else if (cname == CLAIM_TYPE) {
                                                                    c.claimType = reader.nextString()
                                                                } else if (cname == FRIENDLY_NAME) {
                                                                    c.friendlyName = reader.nextString()
                                                                } else if (cname == NAME) {
                                                                    c.name = reader.nextString()
                                                                } else if (cname == VALUE) {
                                                                    val e = parser.parse(reader.nextString())
                                                                    c.value = e
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
                                                    claimsRequired.add(c)
                                                }
                                                reader.endArray()
                                                p.claimsRequired = claimsRequired
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
                                policies.add(p)
                            }
                            reader.endArray()
                            rs.policies = policies
                        } else if (name == SCOPES) {
                            rs.scopes = readSet(reader)
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
            val newId = resourceSetRepository.save(rs).id
            resourceSetOldToNewIdMap[oldId] = newId
        }
        reader.endArray()
        logger.info("Done reading resource sets")
    }


    @Throws(IOException::class)
    private fun readSavedRegisteredClients(reader: JsonReader?) {
        reader!!.beginArray()
        while (reader.hasNext()) {
            var issuer: String? = null
            var clientString: String? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.peek()) {
                    JsonToken.END_OBJECT -> continue
                    JsonToken.NAME -> {
                        val name = reader.nextName()
                        if (reader.peek() == JsonToken.NULL) {
                            reader.skipValue()
                        } else if (name == ISSUER) {
                            issuer = reader.nextString()
                        } else if (name == REGISTERED_CLIENT) {
                            clientString = reader.nextString()
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
            val client = parseRegistered(clientString)
            registeredClientService.save(issuer!!, client!!)
            logger.debug("Saved registered client")
        }
        reader.endArray()
        logger.info("Done reading saved registered clients")
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.MITREidDataServiceExtension#fixExtensionObjectReferences()
	 */
    override fun fixExtensionObjectReferences(maps: MITREidDataServiceMaps) {
        for (permissionId in permissionToResourceRefs.keys) {
            val oldResourceId = permissionToResourceRefs[permissionId]
            val newResourceId = resourceSetOldToNewIdMap[oldResourceId]
            val p = permissionRepository.getById(permissionId.toJavaId())
            val rs = resourceSetRepository.getById(newResourceId.toJavaId())
            p!!.resourceSet = rs
            permissionRepository.saveRawPermission(p)
            logger.debug("Mapping rsid $oldResourceId to $newResourceId for permission $permissionId")
        }
        for (tokenId in tokenToPermissionRefs.keys) {
            val newTokenId = maps.accessTokenOldToNewIdMap[tokenId]
            val token = tokenRepository.getAccessTokenById(newTokenId.toJavaId())!!

            val permissions: MutableSet<Permission> = HashSet()
            for (permissionId in tokenToPermissionRefs[tokenId]!!) {
                val p = permissionRepository.getById(permissionId.toJavaId())!!
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
