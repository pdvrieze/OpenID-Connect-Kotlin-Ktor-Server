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

fun getAsStringSet(o: JsonObject, key: String): Set<String>? {
    return when(val e = o[key]) {
        is JsonPrimitive -> setOf(e.asString())
        is JsonArray -> e.mapTo(HashSet()) { e.asString() }
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
