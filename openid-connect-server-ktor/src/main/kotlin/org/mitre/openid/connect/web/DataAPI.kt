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
package org.mitre.openid.connect.web

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.impl.ktor.MITREidDataService_1_3
import org.mitre.util.getLogger
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.openIdContext
import org.mitre.web.util.requireRole
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

/**
 * API endpoint for importing and exporting the current state of a server.
 * Includes all tokens, grants, whitelists, blacklists, and clients.
 *
 * @author jricher
 */
//@Controller
//@RequestMapping("/api/data")
//@PreAuthorize("hasRole('ROLE_ADMIN')") // you need to be an admin to even think about this -- this is a potentially dangerous API!!
class DataAPI(
    val importers: List<MITREidDataService>,
    val exporter : MITREidDataService_1_3,
) : KtorEndpoint {

    private constructor(service: MITREidDataService_1_3): this(listOf(service), service)

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")

    private val supportedVersions: List<String> = listOf(
        MITREidDataService.MITREID_CONNECT_1_0,
        MITREidDataService.MITREID_CONNECT_1_1,
        MITREidDataService.MITREID_CONNECT_1_2,
        MITREidDataService.MITREID_CONNECT_1_3
    )

    override fun Route.addRoutes() {
        authenticate {
            route("/api/data") {
                post { importData() }
                get { exportData() }
            }
        }
    }

//    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.importData() {
        requireRole(GrantedAuthority.ROLE_ADMIN) { return }
        val data = call.receive<RawData>()

        val config: MITREidDataService.ExtendedConfiguration
        val version: String
        when {
            data.config10 != null -> {
                config = data.config10
                version = MITREidDataService.MITREID_CONNECT_1_0
            }

            data.config11 != null -> {
                config = data.config11
                version = MITREidDataService.MITREID_CONNECT_1_1
            }

            data.config12 != null -> {
                config = data.config12
                version = MITREidDataService.MITREID_CONNECT_1_2
            }

            data.config13 != null -> {
                config = data.config13
                version = MITREidDataService.MITREID_CONNECT_1_3
            }

            else -> throw IllegalArgumentException("no supported version of configuration found")

        }
        val dataService = requireNotNull(importers.firstOrNull { it.supportsVersion(version) }) {
            "No configured service supports version ${version}"
        }

        dataService.importData(config)
        /*
        val jsonReader = JsonReader(reader)

        jsonReader.beginObject()

        while (jsonReader.hasNext()) {
            val tok = jsonReader.peek()
            when (tok) {
                JsonToken.NAME -> {
                    val name = jsonReader.nextName()

                    if (supportedVersions.contains(name)) {
                        // we're working with a known data version tag
                        for (dataService in importers) {
                            // dispatch to the correct service
                            if (dataService.supportsVersion(name)) {
                                dataService.importData(jsonReader)
                                break
                            }
                        }
                    } else {
                        // consume the next bit silently for now
                        logger.debug("Skipping value for $name") // TODO: write these out?
                        jsonReader.skipValue()
                    }
                }

                JsonToken.END_OBJECT -> {}
                JsonToken.END_DOCUMENT -> {}
                JsonToken.BEGIN_ARRAY -> TODO()
                JsonToken.END_ARRAY -> TODO()
                JsonToken.BEGIN_OBJECT -> TODO()
                JsonToken.STRING -> TODO()
                JsonToken.NUMBER -> TODO()
                JsonToken.BOOLEAN -> TODO()
                JsonToken.NULL -> TODO()
            }
        }

        jsonReader.endObject()
*/
        return call.respond(HttpStatusCode.OK)
    }

    @OptIn(ExperimentalSerializationApi::class)
//    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    suspend fun RoutingContext.exportData() {
        val prin = requireRole(GrantedAuthority.ROLE_ADMIN) { return }

        try {
            val conf = buildJsonObject {
                put("exported-at", dateFormat.format(Date()))
                put("exported-from", openIdContext.config.issuer,)
                put("exported-by", prin.name,)
                put(MITREidDataService.MITREID_CONNECT_1_3, json.encodeToJsonElement(exporter.toSerialConfig()))
            }
            return call.respondJson(conf)

        } catch (e: IOException) {
            logger.error("Unable to export data", e)
        }


    }

    @Serializable
    private class RawData(
        @SerialName("mitreid-connect-1.0")
        val config10: MITREidDataService.ExtendedConfiguration10? = null,
        @SerialName("mitreid-connect-1.1")
        val config11: MITREidDataService.ExtendedConfiguration10? = null,
        @SerialName("mitreid-connect-1.2")
        val config12: MITREidDataService.ExtendedConfiguration12? = null,
        @SerialName("mitreid-connect-1.3")
        val config13: MITREidDataService.ExtendedConfiguration12? = null,
    )

    companion object {
        const val URL: String = RootController.API_URL + "/data"

        /**
         * Logger for this class
         */
        private val logger = getLogger<DataAPI>()
    }
}
