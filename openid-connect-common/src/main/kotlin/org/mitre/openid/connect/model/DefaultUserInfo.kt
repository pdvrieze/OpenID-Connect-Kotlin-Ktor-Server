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
package org.mitre.openid.connect.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

//@NamedQueries(NamedQuery(name = DefaultUserInfo.QUERY_BY_USERNAME, query = "select u from DefaultUserInfo u WHERE u.preferredUsername = :" + DefaultUserInfo.PARAM_USERNAME), NamedQuery(name = DefaultUserInfo.QUERY_BY_EMAIL, query = "select u from DefaultUserInfo u WHERE u.email = :" + DefaultUserInfo.PARAM_EMAIL))
@Serializable
class DefaultUserInfo(
    var id: Long? = null,
    override var subject: String,
    override var preferredUsername: String? = null,
    override var name: String? = null,
    override var givenName: String? = null,
    override var familyName: String? = null,
    override var middleName: String? = null,
    override var nickname: String? = null,
    override var profile: String? = null,
    override var picture: String? = null,
    override var website: String? = null,
    override var email: String? = null,
    override var emailVerified: Boolean? = null,
    override var gender: String? = null,
    override var zoneinfo: String? = null,
    override var locale: String? = null,
    override var phoneNumber: String? = null,
    override var phoneNumberVerified: Boolean? = null,
    @SerialName("address")
    private var _address: DefaultAddress? = null,
    override var updatedTime: String? = null,
    override var birthdate: String? = null,
    @Transient
    override var source: JsonObject? = null, // source JSON if this is loaded remotely
) : UserInfo {

    override var address: Address?
        get() = _address
        set(value) {
            _address = value?.let { DefaultAddress.from(it) }
        }

    constructor(
        sub: String,
        preferredUsername: String? = null,
        name: String? = null,
        givenName: String? = null,
        familyName: String? = null,
        middleName: String? = null,
        nickname: String? = null,
        profile: String? = null,
        picture: String? = null,
        website: String? = null,
        email: String? = null,
        emailVerified: Boolean? = null,
        gender: String? = null,
        zoneinfo: String? = null,
        locale: String? = null,
        phoneNumber: String? = null,
        phoneNumberVerified: Boolean? = null,
        address: Address? = null,
        updatedTime: String? = null,
        birthdate: String? = null,
        source: JsonObject? = null,
    ) : this(
        subject = sub,
        preferredUsername = preferredUsername,
        name = name,
        givenName = givenName,
        familyName = familyName,
        middleName = middleName,
        nickname = nickname,
        profile = profile,
        picture = picture,
        website = website,
        email = email,
        emailVerified = emailVerified,
        gender = gender,
        zoneinfo = zoneinfo,
        locale = locale,
        phoneNumber = phoneNumber,
        phoneNumberVerified = phoneNumberVerified,
        _address = address?.let { DefaultAddress.from(it) },
        updatedTime = updatedTime,
        birthdate = birthdate,
        source = source,
    )

    override fun toJson(): JsonObject {
        source?.let { return it }
        return Json.encodeToJsonElement<DefaultUserInfo>(this).jsonObject
    }


    /*
	 * Custom serialization to handle the JSON object
	 */
    @Throws(IOException::class)
    private fun writeObject(out: ObjectOutputStream) {
        out.defaultWriteObject()
        if (source == null) {
            out.writeObject(null)
        } else {
            out.writeObject(source.toString())
        }
    }

    @Throws(IOException::class, ClassNotFoundException::class)
    private fun readObject(input: ObjectInputStream) {
        input.defaultReadObject()
        val o = input.readObject() as String?
        if (o != null) {
            source = Json.encodeToJsonElement(o).jsonObject
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DefaultUserInfo

        if (preferredUsername != other.preferredUsername) return false
        if (name != other.name) return false
        if (givenName != other.givenName) return false
        if (familyName != other.familyName) return false
        if (middleName != other.middleName) return false
        if (nickname != other.nickname) return false
        if (profile != other.profile) return false
        if (picture != other.picture) return false
        if (website != other.website) return false
        if (email != other.email) return false
        if (emailVerified != other.emailVerified) return false
        if (gender != other.gender) return false
        if (zoneinfo != other.zoneinfo) return false
        if (locale != other.locale) return false
        if (phoneNumber != other.phoneNumber) return false
        if (phoneNumberVerified != other.phoneNumberVerified) return false
        if (address != other.address) return false
        if (updatedTime != other.updatedTime) return false
        if (birthdate != other.birthdate) return false

        return true
    }

    override fun hashCode(): Int {
        var result = preferredUsername?.hashCode() ?: 0
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (givenName?.hashCode() ?: 0)
        result = 31 * result + (familyName?.hashCode() ?: 0)
        result = 31 * result + (middleName?.hashCode() ?: 0)
        result = 31 * result + (nickname?.hashCode() ?: 0)
        result = 31 * result + (profile?.hashCode() ?: 0)
        result = 31 * result + (picture?.hashCode() ?: 0)
        result = 31 * result + (website?.hashCode() ?: 0)
        result = 31 * result + (email?.hashCode() ?: 0)
        result = 31 * result + (emailVerified?.hashCode() ?: 0)
        result = 31 * result + (gender?.hashCode() ?: 0)
        result = 31 * result + (zoneinfo?.hashCode() ?: 0)
        result = 31 * result + (locale?.hashCode() ?: 0)
        result = 31 * result + (phoneNumber?.hashCode() ?: 0)
        result = 31 * result + (phoneNumberVerified?.hashCode() ?: 0)
        result = 31 * result + (address?.hashCode() ?: 0)
        result = 31 * result + (updatedTime?.hashCode() ?: 0)
        result = 31 * result + (birthdate?.hashCode() ?: 0)
        return result
    }

    companion object {
        const val QUERY_BY_USERNAME: String = "DefaultUserInfo.getByUsername"
        const val QUERY_BY_EMAIL: String = "DefaultUserInfo.getByEmailAddress"

        const val PARAM_USERNAME: String = "username"
        const val PARAM_EMAIL: String = "email"

        private const val serialVersionUID = 6078310513185681918L

        /**
         * Parse a JsonObject into a UserInfo.
         */
        @JvmStatic
        fun fromJson(obj: JsonObject): UserInfo {
            return Json.decodeFromJsonElement<DefaultUserInfo>(obj)
        }

        private fun nullSafeGetString(obj: JsonObject, field: String): String? {
            return (obj[field] as? JsonPrimitive)?.toString()
        }

        fun from(info: UserInfo): DefaultUserInfo {
            return info as? DefaultUserInfo ?: DefaultUserInfo(
                subject = info.subject,
                        preferredUsername = info.preferredUsername,
                        name = info.name,
                        givenName = info.givenName,
                        familyName = info.familyName,
                        middleName = info.middleName,
                        nickname = info.nickname,
                        profile = info.profile,
                        picture = info.picture,
                        website = info.website,
                        email = info.email,
                        emailVerified = info.emailVerified,
                        gender = info.gender,
                        zoneinfo = info.zoneinfo,
                        locale = info.locale,
                        phoneNumber = info.phoneNumber,
                        phoneNumberVerified = info.phoneNumberVerified,
                        _address = info.address?.let { DefaultAddress.from(it) },
                        updatedTime = info.updatedTime,
                        birthdate = info.birthdate,
                        source = info.source,
            )
        }
    }
}
