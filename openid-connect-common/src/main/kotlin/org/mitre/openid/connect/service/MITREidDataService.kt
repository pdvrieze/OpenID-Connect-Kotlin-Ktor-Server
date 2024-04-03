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
package org.mitre.openid.connect.service

import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonWriter
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.format.datetime.DateFormatter
import java.io.IOException
import java.io.StringReader
import java.text.ParseException
import java.time.Instant
import java.util.*

/**
 * @author jricher
 * @author arielak
 */
interface MITREidDataService {
    /**
     * Write out the current server state to the given JSON writer as a JSON object
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    fun exportData(writer: JsonWriter)

    /**
     * Read in the current server state from the given JSON reader as a JSON object
     */
    @Throws(IOException::class)
    fun importData(reader: JsonReader)

    /**
     * Read in the state from a string
     */
    fun importData(configJson: String) {
        val reader = JsonReader(StringReader(configJson))
        importData(reader)
    }

    /**
     * Return true if the this data service supports the given version. This is called before
     * handing the service the reader through its importData function.
     *
     */
    fun supportsVersion(version: String?): Boolean

    companion object {
        private val dateFormatter = DateFormatter().apply {
            setIso(DateTimeFormat.ISO.DATE_TIME)
        }

        @JvmStatic
        public fun utcToInstant(value: String?): Instant? {
            if (value == null) return null

            try {
                return dateFormatter.parse(value, Locale.ENGLISH).toInstant()
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun utcToDate(value: String?): Date? {
            if (value == null) return null

            try {
                return dateFormatter.parse(value, Locale.ENGLISH)
            } catch (ex: ParseException) {
                logger.error("Unable to parse datetime {}", value, ex)
            }
            return null
        }

        @JvmStatic
        public fun toUTCString(value: Instant?): String? {
            if (value == null) return null

            return dateFormatter.print(Date.from(value), Locale.ENGLISH)
        }

        @JvmStatic
        public fun toUTCString(value: Date?): String? {
            if (value == null) return null

            return dateFormatter.print(value, Locale.ENGLISH)
        }

        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(MITREidDataService::class.java)
        val json: Json = Json {
            ignoreUnknownKeys = true
            prettyPrint = true
        }


        /**
         * Data member for 1.X configurations
         */
        const val MITREID_CONNECT_1_0: String = "mitreid-connect-1.0"
        const val MITREID_CONNECT_1_1: String = "mitreid-connect-1.1"
        const val MITREID_CONNECT_1_2: String = "mitreid-connect-1.2"
        const val MITREID_CONNECT_1_3: String = "mitreid-connect-1.3"

        // member names
        const val REFRESHTOKENS: String = "refreshTokens"
        const val ACCESSTOKENS: String = "accessTokens"
        const val WHITELISTEDSITES: String = "whitelistedSites"
        const val BLACKLISTEDSITES: String = "blacklistedSites"
        const val AUTHENTICATIONHOLDERS: String = "authenticationHolders"
        const val GRANTS: String = "grants"
        const val CLIENTS: String = "clients"
        const val SYSTEMSCOPES: String = "systemScopes"
    }

    interface ConfigurationData {

    }

/*
    abstract class ConfigurationSerializerBase<T: ConfigurationData>(val name: String, val version: String, val extensions: List<MITREidDataServiceExtension>) : KSerializer<T> {

        private val elementSerializers: List<Pair<String, KSerializer<*>>> by lazy {
            buildList {
                addBaseElements()
            }
        }


        override val descriptor: SerialDescriptor by lazy {
            buildClassSerialDescriptor(name) {
                for((name, serializer) in elementSerializers) {
                    element(name, serializer.descriptor)
                }
            }
        }

        open fun MutableList<ElementSerializer>.addBaseElements() {
            add(ElementSerializer(CLIENTS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(GRANTS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(WHITELISTEDSITES, ListSerializer(WhitelistedSite.serializer()), false))
            add(ElementSerializer(BLACKLISTEDSITES, ListSerializer(BlacklistedSite.serializer()), false))
            add(ElementSerializer(AUTHENTICATIONHOLDERS, ListSerializer(AuthenticationHolderEntity.serializer()), false))
            add(ElementSerializer(ACCESSTOKENS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(REFRESHTOKENS, ListSerializer(JsonElement.serializer()), false))
            add(ElementSerializer(SYSTEMSCOPES, ListSerializer(SystemScope.serializer()), false))
        }

    }
*/

}

internal data class ElementSerializer(val name: String, val serializer: KSerializer<*>, val isOptional: Boolean)
