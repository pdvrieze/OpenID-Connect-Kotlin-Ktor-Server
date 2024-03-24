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
/**
 *
 */
package org.mitre.util

import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import com.google.gson.stream.JsonWriter
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.*

/**
 * A collection of null-safe converters from common classes and JSON elements, using GSON.
 *
 * @author jricher
 */
object JsonUtils {
    /**
     * Logger for this class
     */
    private val logger: Logger = LoggerFactory.getLogger(JsonUtils::class.java)

    private val gson = Gson()

    /**
     * Translate a set of strings to a JSON array, empty array returned as null
     */
    @JvmStatic
    fun getAsArray(value: Set<String>?): JsonElement {
        return getAsArray(value, false)
    }


    /**
     * Translate a set of strings to a JSON array, optionally preserving the empty array. Otherwise (default) empty array is returned as null.
     */
    @JvmStatic
    fun getAsArray(value: Set<String>?, preserveEmpty: Boolean): JsonElement {
        return if (!preserveEmpty && value != null && value.isEmpty()) {
            // if we're not preserving empty arrays and the value is empty, return null
            JsonNull.INSTANCE
        } else {
            gson.toJsonTree(value, object : TypeToken<Set<String>>() {}.type)
        }
    }

    /**
     * Gets the value of the given member (expressed as integer seconds since epoch) as a Date
     */
    @JvmStatic
    fun getAsDate(o: JsonObject, member: String?): Date? {
        if (o.has(member)) {
            val e = o[member]
            return if (e?.isJsonPrimitive == true) {
                Date(e.asInt * 1000L)
            } else {
                null
            }
        } else {
            return null
        }
    }

    /**
     * Gets the value of the given member as a JWE Algorithm, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJweAlgorithm(o: JsonObject, member: String?): JWEAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> JWEAlgorithm.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a JWE Encryption Method, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJweEncryptionMethod(o: JsonObject, member: String?): EncryptionMethod? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> EncryptionMethod.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a JWS Algorithm, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJwsAlgorithm(o: JsonObject, member: String?): JWSAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> JWSAlgorithm.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a PKCE Algorithm, null if it doesn't exist
     */
    @JvmStatic
    fun getAsPkceAlgorithm(o: JsonObject, member: String?): PKCEAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> parse(s)
        }
    }

    /**
     * Gets the value of the given member as a string, null if it doesn't exist
     */
    @JvmStatic
    fun getAsString(o: JsonObject, member: String?): String? {
        val e = o[member]
        return when {
            e!=null && e.isJsonPrimitive -> e.asString
            else -> null
        }
    }

    /**
     * Gets the value of the given member as a boolean, null if it doesn't exist
     */
    @JvmStatic
    fun getAsBoolean(o: JsonObject, member: String?): Boolean? {
        val e = o[member]
        return when {
            e!=null && e.isJsonPrimitive -> e.asBoolean
            else -> null
        }
    }

    /**
     * Gets the value of the given member as a Long, null if it doesn't exist
     */
    @JvmStatic
    fun getAsLong(o: JsonObject, member: String?): Long? {
        val e = o[member]
        return when {
            e!=null && e.isJsonPrimitive -> e.asLong
            else -> null
        }
    }

    /**
     * Gets the value of the given given member as a set of strings, null if it doesn't exist
     */
    @Throws(JsonSyntaxException::class)
    @JvmStatic
    fun getAsStringSet(o: JsonObject, member: String?): Set<String>? {
        val e = o[member]
        return when {
            e == null -> null
            e.isJsonArray -> gson.fromJson<Set<String>>(e, object : TypeToken<Set<String>>() {}.type)
            else -> HashSet<String>().apply { add(e.asString) }
        }
    }

    /**
     * Gets the value of the given given member as a set of strings, null if it doesn't exist
     */
    @Throws(JsonSyntaxException::class)
    @JvmStatic
    fun getAsStringList(o: JsonObject, member: String?): List<String>? {
        val e = o[member]
        return when {
            e == null -> null
            e.isJsonArray -> gson.fromJson<List<String>>(e, object : TypeToken<List<String>>() {}.type)
            else -> listOf(e.asString)
        }
    }

    /**
     * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJwsAlgorithmList(o: JsonObject, member: String?): List<JWSAlgorithm>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { JWSAlgorithm.parse(it) }
    }

    /**
     * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJweAlgorithmList(o: JsonObject, member: String?): List<JWEAlgorithm>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { JWEAlgorithm.parse(it) }
    }

    /**
     * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
     */
    @JvmStatic
    fun getAsEncryptionMethodList(o: JsonObject, member: String?): List<EncryptionMethod>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { EncryptionMethod.parse(it) }
    }

    @Throws(IOException::class)
    @JvmStatic
    fun <V: Any> readMap(reader: JsonReader): Map<String, V> {
        val map: MutableMap<Any, Any> = HashMap<Any, Any>()
        reader.beginObject()
        while (reader.hasNext()) {
            val name = reader.nextName()
            var value: Any? = null
            value = when (reader.peek()) {
                JsonToken.STRING -> reader.nextString()
                JsonToken.BOOLEAN -> reader.nextBoolean()
                JsonToken.NUMBER -> reader.nextLong()
                else -> {
                    logger.debug("Found unexpected entry")
                    reader.skipValue()
                    continue
                }
            }
            map[name] = value
        }
        reader.endObject()
        @Suppress("UNCHECKED_CAST")
        return map as Map<String, V>
    }

    @Throws(IOException::class)
    @JvmStatic
    fun <V> readSet(reader: JsonReader): Set<V> {
        var arraySet: MutableSet<*>? = null
        reader.beginArray()
        when (reader.peek()) {
            JsonToken.STRING -> {
                arraySet = HashSet<String>()
                while (reader.hasNext()) {
                    arraySet.add(reader.nextString())
                }
            }

            JsonToken.NUMBER -> {
                arraySet = HashSet<Long>()
                while (reader.hasNext()) {
                    arraySet.add(reader.nextLong())
                }
            }

            else -> arraySet = HashSet<Any>()
        }
        reader.endArray()
        @Suppress("UNCHECKED_CAST")
        return arraySet as Set<V>
    }

    @Throws(IOException::class)
    @JvmStatic
    fun writeNullSafeArray(writer: JsonWriter, items: Set<String>?) {
        if (items != null) {
            writer.beginArray()
            for (s in items) {
                writer.value(s)
            }
            writer.endArray()
        } else {
            writer.nullValue()
        }
    }
}
