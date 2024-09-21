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

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.impl.MITREidDataService_1_3
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import java.io.IOException
import java.io.InputStream
import java.security.Principal
import java.text.SimpleDateFormat
import java.util.*
import javax.servlet.http.HttpServletResponse

/**
 * API endpoint for importing and exporting the current state of a server.
 * Includes all tokens, grants, whitelists, blacklists, and clients.
 *
 * @author jricher
 */
@Controller
@RequestMapping("/" + DataAPI.URL)
@PreAuthorize("hasRole('ROLE_ADMIN')") // you need to be an admin to even think about this -- this is a potentially dangerous API!!
class DataAPI {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ")

    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    @Autowired
    private lateinit var importers: List<MITREidDataService>

    private val supportedVersions: List<String> = listOf(
        MITREidDataService.MITREID_CONNECT_1_0,
        MITREidDataService.MITREID_CONNECT_1_1,
        MITREidDataService.MITREID_CONNECT_1_2,
        MITREidDataService.MITREID_CONNECT_1_3
    )

    @Autowired
    private lateinit var exporter: MITREidDataService_1_3

    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE])
    @Throws(IOException::class)
    fun importData(inStream: InputStream, m: Model?): String {
        val data = MITREidDataService.json.decodeFromStream<RawData>(inStream)
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
        return "httpCodeView"
    }

    @OptIn(ExperimentalSerializationApi::class)
    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    @Throws(IOException::class)
    fun exportData(resp: HttpServletResponse, prin: Principal) {
        resp.contentType = MediaType.APPLICATION_JSON_VALUE

        val out = resp.outputStream

        val conf = mapOf(
            "exported-at" to dateFormat.format(Date()),
            "exported-from" to config.issuer,
            "exported-by" to prin.name,
            MITREidDataService.MITREID_CONNECT_1_3 to exporter.toSerialConfig()
        )

        try {
            MITREidDataService.json.encodeToStream(conf, out)
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
