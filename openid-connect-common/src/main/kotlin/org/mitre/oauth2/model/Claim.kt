package org.mitre.oauth2.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.util.asBoolean
import org.mitre.util.asLong
import org.mitre.util.asString
import org.mitre.util.oidJson
import java.time.Instant
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class Claim {

    abstract class Key<T>(val name: String) {
        abstract fun fromJson(e: JsonElement): T
        abstract fun toJson(value: T): JsonElement

        override fun hashCode(): Int = name.hashCode()

        override fun equals(other: Any?): Boolean {
            return other is Key<*> && other.name == name
        }
    }
    class StringKey(name: String) : Key<String>(name) {
        override fun fromJson(e: JsonElement): String = e.asString()
        override fun toJson(value: String): JsonElement = JsonPrimitive(value)
    }
    class StringListKey(name: String, val shorthand: Boolean) : Key<List<String>>(name) {
        override fun fromJson(e: JsonElement): List<String> = when (e) {
            is JsonArray -> e.map { it.asString() }
            else -> listOf(e.asString())
        }
        override fun toJson(value: List<String>): JsonElement = when {
            shorthand && value.size == 1 -> JsonPrimitive(value.first())
            else -> buildJsonArray { value.forEach() { add(JsonPrimitive(it)) } }
        }
    }
    @OptIn(ExperimentalEncodingApi::class)
    class Base64Key(name: String) : Key<ByteArray>(name) {
        override fun fromJson(e: JsonElement): ByteArray = Base64.UrlSafe.decode(e.asString())
        override fun toJson(value: ByteArray): JsonElement = JsonPrimitive(Base64.UrlSafe.encode(value))
    }
    class InstantKey(name: String) : Key<Instant>(name) {
        override fun fromJson(e: JsonElement): Instant = Instant.ofEpochSecond(e.asLong())
        override fun toJson(value: Instant): JsonElement = JsonPrimitive(value.epochSecond)
    }
    class BooleanKey(name: String) : Key<Boolean>(name) {
        override fun fromJson(e: JsonElement): Boolean = e.asBoolean()
        override fun toJson(value: Boolean): JsonElement = JsonPrimitive(value)
    }
    open class SerializableKey<T>(name: String, val serializer: KSerializer<T>) : Key<T>(name) {
        override fun fromJson(e: JsonElement): T = oidJson.decodeFromJsonElement(serializer, e)
        override fun toJson(value: T): JsonElement = oidJson.encodeToJsonElement(serializer, value)
    }
    class AddressKey(name: String) : SerializableKey<DefaultAddress>(name, DefaultAddress.serializer())
    class JsonKey(name: String) : Key<JsonElement>(name) {
        override fun fromJson(e: JsonElement): JsonElement = e
        override fun toJson(value: JsonElement): JsonElement = value
    }

    companion object {
        val AT_HASH = Base64Key("at_hash")
        val C_HASH = Base64Key("c_hash")

        /** URL of the authorization service */
        val ISSUER = StringKey("iss")
        /** The intended recipient. This should contain the client_id of the relying parties */
        val AUDIENCE = StringListKey("aud", true)
        /** Expiration after which the token is no longer valid */
        val EXPIRATION = InstantKey("exp")
        /** The time at which the token was issued */
        val ISSUED_AT = InstantKey("iat")
        /** The time at which the end user was authenticated */
        val AUTHENTICATION_TIME = InstantKey("auth_time")
        /** Security nonce allowing the client to defend against replay attacks */
        val NONCE = StringKey("nonce")
        /** Authentication context class reference */
        val AUTH_CONTEXT_CLASS = StringKey("acr")
        /** Authentication methods references */
        val AUTH_METHOD_REFS = StringListKey("amr", false)
        /** The authorized party, includes the client_id of the authorized parties */
        val AUTHZ_PARTY = StringListKey("azp", false)

        /** Identifier for the end-user at the issuer */
        val SUB = StringKey("sub")
        /** End user's full name */
        val NAME = StringKey("name")
        val GIVEN_NAME = StringKey("given_name")
        val FAMILY_NAME = StringKey("family_name")
        val MIDDLE_NAME = StringKey("middle_name")
        val NICKNAME = StringKey("nickname")
        val PREFERRED_USERNAME = StringKey("preferred_username")
        val PROFILE = StringKey("profile")
        val PICTURE = StringKey("picture")
        val WEBSITE = StringKey("website")
        val EMAIL = StringKey("email")
        val EMAIL_VERIFIED = BooleanKey("email_verified")
        val GENDER = StringKey("gender")
        val BIRTHDATE = StringKey("birthdate")
        val ZONEINFO = StringKey("zoneinfo")
        val LOCALE = StringKey("locale")
        val PHONE_NUMBER = StringKey("phone_number")
        val PHONE_NUMBER_VERIFIED = BooleanKey("phone_number_verified")
        val ADDRESS = AddressKey("address")
        val UPDATED_AT = InstantKey("updated_at")


        val standardOidTokenClaims: Map<String, Key<*>> =  listOf(
            ISSUER,
            SUB,
            AUDIENCE,
            EXPIRATION,
            ISSUED_AT,
            AUTHENTICATION_TIME,
            NONCE,
            AUTH_CONTEXT_CLASS,
            AUTH_METHOD_REFS,
            AUTHZ_PARTY,
        ).associateBy { it.name }

        val standardOidInfoClaims: Map<String, Key<*>> = listOf(
            SUB,
            NAME,
            GIVEN_NAME,
            FAMILY_NAME,
            MIDDLE_NAME,
            NICKNAME,
            PREFERRED_USERNAME,
            PROFILE,
            PICTURE,
            WEBSITE,
            EMAIL,
            EMAIL_VERIFIED,
            GENDER,
            BIRTHDATE,
            ZONEINFO,
            LOCALE,
            PHONE_NUMBER,
            PHONE_NUMBER_VERIFIED,
            ADDRESS,
            UPDATED_AT,
        ).associateBy { it.name }
    }

}
