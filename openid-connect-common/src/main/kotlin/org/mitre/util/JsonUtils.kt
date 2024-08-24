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
package org.mitre.util

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.PKCEAlgorithm.Companion.parse
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.*
import kotlin.collections.HashSet
import com.google.gson.JsonElement as GsonElement
import com.google.gson.JsonNull as GsonNull
import com.google.gson.JsonObject as GsonObject
import com.google.gson.stream.JsonReader as GsonReader
import com.google.gson.stream.JsonToken as GsonToken
import com.google.gson.stream.JsonWriter as GsonWriter

/**
 * A collection of null-safe converters from common classes and JSON elements, using GSON.
 *
 * @author jricher
 */
object GsonUtils {
    /**
     * Logger for this class
     */
    private val logger: Logger = LoggerFactory.getLogger(GsonUtils::class.java)

    private val gson = Gson()

    /**
     * Translate a set of strings to a JSON array, empty array returned as null
     */
    @JvmStatic
    fun getAsArray(value: Set<String>?): GsonElement {
        return getAsArray(value, false)
    }


    /**
     * Translate a set of strings to a JSON array, optionally preserving the empty array. Otherwise (default) empty array is returned as null.
     */
    @JvmStatic
    fun getAsArray(value: Set<String>?, preserveEmpty: Boolean): GsonElement {
        return if (!preserveEmpty && value != null && value.isEmpty()) {
            // if we're not preserving empty arrays and the value is empty, return null
            GsonNull.INSTANCE
        } else {
            gson.toJsonTree(value, object : TypeToken<Set<String>>() {}.type)
        }
    }

    /**
     * Gets the value of the given member (expressed as integer seconds since epoch) as a Date
     */
    @JvmStatic
    fun getAsDate(o: GsonObject, member: String?): Date? {
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
    fun getAsJweAlgorithm(o: GsonObject, member: String?): JWEAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> JWEAlgorithm.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a JWE Encryption Method, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJweEncryptionMethod(o: GsonObject, member: String?): EncryptionMethod? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> EncryptionMethod.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a JWS Algorithm, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJwsAlgorithm(o: GsonObject, member: String?): JWSAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> JWSAlgorithm.parse(s)
        }
    }

    /**
     * Gets the value of the given member as a PKCE Algorithm, null if it doesn't exist
     */
    @JvmStatic
    fun getAsPkceAlgorithm(o: GsonObject, member: String?): PKCEAlgorithm? {
        return when (val s = getAsString(o, member)) {
            null -> null
            else -> parse(s)
        }
    }

    /**
     * Gets the value of the given member as a string, null if it doesn't exist
     */
    @JvmStatic
    fun getAsString(o: GsonObject, member: String?): String? {
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
    fun getAsBoolean(o: GsonObject, member: String?): Boolean? {
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
    fun getAsLong(o: GsonObject, member: String?): Long? {
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
    fun getAsStringSet(o: GsonObject, member: String?): Set<String>? {
        val e = o[member]
        return when {
            e == null -> null
            e.isJsonArray -> gson.fromJson<Set<String>>(e, object : TypeToken<Set<String>>() {}.type)
            else -> HashSet<String>().apply { add(e.asString) }
        }
    }

    /**
     * Gets the value of the given member as a set of strings, null if it doesn't exist
     */
    @Throws(JsonSyntaxException::class)
    @JvmStatic
    fun getAsStringSet(o: JsonObject, member: String?): Set<String>? {
        val e = o[member]
        return when {
            e == null -> null
            e is JsonArray -> e.mapTo(HashSet()) { it.asString() }
            else -> HashSet<String>().apply { add(e.asString()) }
        }
    }

    /**
     * Gets the value of the given given member as a set of strings, null if it doesn't exist
     */
    @Throws(JsonSyntaxException::class)
    @JvmStatic
    fun getAsStringList(o: GsonObject, member: String?): List<String>? {
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
    fun getAsJwsAlgorithmList(o: GsonObject, member: String?): List<JWSAlgorithm>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { JWSAlgorithm.parse(it) }
    }

    /**
     * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
     */
    @JvmStatic
    fun getAsJweAlgorithmList(o: GsonObject, member: String?): List<JWEAlgorithm>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { JWEAlgorithm.parse(it) }
    }

    /**
     * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
     */
    @JvmStatic
    fun getAsEncryptionMethodList(o: GsonObject, member: String?): List<EncryptionMethod>? {
        val strings = getAsStringList(o, member) ?: return null
        return strings.map { EncryptionMethod.parse(it) }
    }

    @Throws(IOException::class)
    @JvmStatic
    fun <V: Any> readMap(reader: GsonReader): Map<String, V> {
        val map: MutableMap<Any, Any> = HashMap<Any, Any>()
        reader.beginObject()
        while (reader.hasNext()) {
            val name = reader.nextName()
            var value: Any? = null
            value = when (reader.peek()) {
                GsonToken.STRING -> reader.nextString()
                GsonToken.BOOLEAN -> reader.nextBoolean()
                GsonToken.NUMBER -> reader.nextLong()
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
    fun <V> readSet(reader: GsonReader): Set<V> {
        var arraySet: MutableSet<*>? = null
        reader.beginArray()
        when (reader.peek()) {
            GsonToken.STRING -> {
                arraySet = HashSet<String>()
                while (reader.hasNext()) {
                    arraySet.add(reader.nextString())
                }
            }

            GsonToken.NUMBER -> {
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
    fun writeNullSafeArray(writer: GsonWriter, items: Set<String>?) {
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

fun JsonPrimitive.asString(): String {
    require(isString) { "The primitive found is not a string" }
    return content
}

fun JsonElement.asString(): String {
    require(this is JsonPrimitive) { "String expected, but found other type: ${javaClass.name}" }
    return asString()
}

fun JsonPrimitive.asStringOrNull(): String? {
    if (!isString) return null
    return content
}

fun JsonElement.asStringOrNull(): String? {
    if (this !is JsonPrimitive) return null
    return asStringOrNull()
}

fun JsonPrimitive.asBooleanOrNull(): Boolean? {
    if (isString) return null
    return booleanOrNull
}

fun JsonElement.asBooleanOrNull(): Boolean? {
    if (this !is JsonPrimitive) return null
    return asBooleanOrNull()
}

fun JsonPrimitive.asBoolean(): Boolean {
    require(!isString) { "Expected boolean, found string"}
    return boolean
}

fun JsonElement.asBoolean(): Boolean {
    require(this is JsonPrimitive) { "Expected Json primitive, found: ${javaClass.name}" }
    return asBoolean()
}

@Deprecated("Use contains", ReplaceWith("contains(key)"))
fun JsonObject.has(key: String) = contains(key)

@Deprecated("Use extension", ReplaceWith("e[key]?.asStringOrNull()", "org.mitre.util.asStringOrNull"))
fun getAsString(o: JsonObject, key: String): String? {
    val v = (o[key] as? JsonPrimitive) ?: return null
    if (! v.isString) return null
    return v.content
}

@Deprecated("Use extension", ReplaceWith("o[key]?.asBooleanOrNull()", "org.mitre.util.asStringOrNull"))
fun getAsBoolean(o: JsonObject, key: String): Boolean? {
    val v = (o[key] as? JsonPrimitive) ?: return null
    if (v.isString) return null
    return v.boolean
}

fun getAsStringList(o: JsonObject, key: String): List<String>? {
    return when(val e = o[key]) {
        is JsonPrimitive -> listOf(e.asString())
        is JsonArray -> e.map { e.asString() }
        else -> null
    }
}

fun getAsJwsAlgorithmList(o: JsonObject, key: String): List<JWSAlgorithm>? {
    return getAsStringList(o, key)?.map { JWSAlgorithm.parse(it) }
}
/**
 * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
 */
fun getAsJweAlgorithmList(o: JsonObject, key: String): List<JWEAlgorithm>? {
    return getAsStringList(o, key)?.map { JWEAlgorithm.parse(it) }
}

/**
 * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
 */
fun getAsEncryptionMethodList(o: JsonObject, member: String): List<EncryptionMethod>? {
    return getAsStringList(o, member)?.map { EncryptionMethod.parse(it) }
}

@Deprecated("Check directly", ReplaceWith("this is JsonArray", " kotlinx.serialization.json.JsonArray"))
val JsonElement?.isJsonArray get() = this is JsonArray

@Deprecated("Check directly", ReplaceWith("this is JsonObject", " kotlinx.serialization.json.JsonObject"))
val JsonElement?.isJsonObject get() = this is JsonObject

@Deprecated("Check directly", ReplaceWith("this is JsonNull", " kotlinx.serialization.json.JsonNull"))
val JsonElement?.isJsonNull get() = this is JsonNull
