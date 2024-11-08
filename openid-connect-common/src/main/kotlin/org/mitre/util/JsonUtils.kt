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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull

fun JsonPrimitive.asString(): String {
    require(isString) { "The primitive found is not a string" }
    return content
}

fun JsonElement?.asLong(): Long {
    require(this is JsonPrimitive) { "The element is not a primitive : ${this?.javaClass?.simpleName}" }
    require(!isString) { "Json long expected, but found string" }
    return content.toLong()
}

fun JsonElement?.asString(): String {
    require(this is JsonPrimitive) { "The element is not a primitive : ${this?.javaClass?.simpleName} - '${toString()}'"}
    require(isString) { "Json string expected, but found other type: ${this.javaClass.name}" }
    return content
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
    if (this !is JsonPrimitive || isString) return null
    return booleanOrNull
}

fun JsonElement?.asBoolean(): Boolean {
    require(this is JsonPrimitive) { "Expected Json primitive with boolean, found: ${this?.javaClass?.name}" }
    return boolean
}

@Deprecated("Use contains", ReplaceWith("contains(key)"))
fun JsonObject.has(key: String) = contains(key)

fun JsonElement?.asStringList(): List<String>? {
    return when (this) {
        is JsonPrimitive -> listOf(asString())
        is JsonArray -> map { asString() }
        else -> null
    }
}

fun JsonElement?.asStringSet(): Set<String>? {
    return when (this) {
        is JsonPrimitive -> setOf(asString())
        is JsonArray -> mapTo(HashSet()) { asString() }
        else -> null
    }
}

/**
 * Gets the value of the given member as a list of JWS Algorithms, null if it doesn't exist
 */
fun JsonElement?.asJwsAlgorithmList(): List<JWSAlgorithm>? {
    return when (this) {
        is JsonPrimitive -> listOf(JWSAlgorithm.parse(asString()))
        is JsonArray -> map { JWSAlgorithm.parse(asString()) }
        else -> null
    }
}

/**
 * Gets the value of the given member as a list of JWE Algorithms, null if it doesn't exist
 */
fun JsonElement?.asJweAlgorithmList(): List<JWEAlgorithm>? {
    return when (this) {
        is JsonPrimitive -> listOf(JWEAlgorithm.parse(asString()))
        is JsonArray -> map { JWEAlgorithm.parse(asString()) }
        else -> null
    }
}

/**
 * Gets the value of the given member as a list of JWS encryption methods, null if it doesn't exist
 */
fun JsonElement?.asEncryptionMethodList(): List<EncryptionMethod>? {
    return when (this) {
        is JsonPrimitive -> listOf(EncryptionMethod.parse(asString()))
        is JsonArray -> map { EncryptionMethod.parse(asString()) }
        else -> null
    }
}

val oidJson: Json = Json {
    ignoreUnknownKeys = true
    prettyPrint = true
    prettyPrintIndent = "  "
}
