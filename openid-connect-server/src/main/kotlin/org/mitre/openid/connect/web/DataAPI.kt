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

import com.google.common.collect.ImmutableList
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import org.mitre.openid.connect.config.ConfigurationPropertiesBean
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.impl.MITREidDataService_1_3
import org.mitre.openid.connect.web.DataAPI
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import java.io.IOException
import java.io.Reader
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

    private val supportedVersions: List<String> = ImmutableList.of(
        MITREidDataService.MITREID_CONNECT_1_0,
        MITREidDataService.MITREID_CONNECT_1_1,
        MITREidDataService.MITREID_CONNECT_1_2,
        MITREidDataService.MITREID_CONNECT_1_3
    )

    @Autowired
    private lateinit var exporter: MITREidDataService_1_3

    @RequestMapping(method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE])
    @Throws(IOException::class)
    fun importData(`in`: Reader?, m: Model?): String {
        val reader = JsonReader(`in`)

        reader.beginObject()

        while (reader.hasNext()) {
            val tok = reader.peek()
            when (tok) {
                JsonToken.NAME -> {
                    val name = reader.nextName()

                    if (supportedVersions.contains(name)) {
                        // we're working with a known data version tag
                        for (dataService in importers) {
                            // dispatch to the correct service
                            if (dataService.supportsVersion(name)) {
                                dataService.importData(reader)
                                break
                            }
                        }
                    } else {
                        // consume the next bit silently for now
                        logger.debug("Skipping value for $name") // TODO: write these out?
                        reader.skipValue()
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

        reader.endObject()

        return "httpCodeView"
    }

    @RequestMapping(method = [RequestMethod.GET], produces = [MediaType.APPLICATION_JSON_VALUE])
    @Throws(IOException::class)
    fun exportData(resp: HttpServletResponse, prin: Principal) {
        resp.contentType = MediaType.APPLICATION_JSON_VALUE

        // this writer puts things out onto the wire
        val writer = JsonWriter(resp.writer)
        writer.setIndent("  ")

        try {
            writer.beginObject()

            writer.name("exported-at")
            writer.value(dateFormat.format(Date()))

            writer.name("exported-from")
            writer.value(config.issuer)

            writer.name("exported-by")
            writer.value(prin.name)

            // delegate to the service to do the actual export
            exporter.exportData(writer)

            writer.endObject() // end root
            writer.close()
        } catch (e: IOException) {
            logger.error("Unable to export data", e)
        }
    }

    companion object {
        const val URL: String = RootController.API_URL + "/data"

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(DataAPI::class.java)
    }
}
