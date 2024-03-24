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

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.mitre.openid.connect.model.DefaultAddress
import org.mitre.openid.connect.model.convert.JsonObjectStringConverter
import java.io.IOException
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import javax.persistence.Basic
import javax.persistence.CascadeType
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.NamedQueries
import javax.persistence.NamedQuery
import javax.persistence.OneToOne
import javax.persistence.Table

@Entity
@Table(name = "user_info")
@NamedQueries(NamedQuery(name = DefaultUserInfo.QUERY_BY_USERNAME, query = "select u from DefaultUserInfo u WHERE u.preferredUsername = :" + DefaultUserInfo.PARAM_USERNAME), NamedQuery(name = DefaultUserInfo.QUERY_BY_EMAIL, query = "select u from DefaultUserInfo u WHERE u.email = :" + DefaultUserInfo.PARAM_EMAIL))
class DefaultUserInfo : UserInfo {
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    var id: Long? = null

    @get:Basic
    @get:Column(name = "sub")
    override var sub: String? = null

    @Basic
    @Column(name = "preferred_username")
    override var preferredUsername: String? = null

    @Basic
    @Column(name = "name")
    override var name: String? = null

    @Basic
    @Column(name = "given_name")
    override var givenName: String? = null

    @Basic
    @Column(name = "family_name")
    override var familyName: String? = null

    @Basic
    @Column(name = "middle_name")
    override var middleName: String? = null

    @Basic
    @Column(name = "nickname")
    override var nickname: String? = null

    @Basic
    @Column(name = "profile")
    override var profile: String? = null

    @Basic
    @Column(name = "picture")
    override var picture: String? = null

    @Basic
    @Column(name = "website")
    override var website: String? = null

    @Basic
    @Column(name = "email")
    override var email: String? = null

    @Basic
    @Column(name = "email_verified")
    override var emailVerified: Boolean? = null

    @Basic
    @Column(name = "gender")
    override var gender: String? = null

    @Basic
    @Column(name = "zone_info")
    override var zoneinfo: String? = null

    @Basic
    @Column(name = "locale")
    override var locale: String? = null

    @Basic
    @Column(name = "phone_number")
    override var phoneNumber: String? = null

    @Basic
    @Column(name = "phone_number_verified")
    override var phoneNumberVerified: Boolean? = null

    @OneToOne(targetEntity = DefaultAddress::class, cascade = [CascadeType.ALL])
    @JoinColumn(name = "address_id")
    override var address: Address? = null
        set(value) {
            field = address?.let { it as? DefaultAddress ?: DefaultAddress(it) }
        }

    @Basic
    @Column(name = "updated_time")
    override var updatedTime: String? = null


    @Basic
    @Column(name = "birthdate")
    override var birthdate: String? = null

    @get:Convert(converter = JsonObjectStringConverter::class)
    @get:Column(name = "src")
    @get:Basic
    @Transient
    override var source: JsonObject? = null // source JSON if this is loaded remotely


    override fun toJson(): JsonObject? {
        if (source == null) {
            val obj = JsonObject()

            obj.addProperty("sub", this.sub)

            obj.addProperty("name", this.name)
            obj.addProperty("preferred_username", this.preferredUsername)
            obj.addProperty("given_name", this.givenName)
            obj.addProperty("family_name", this.familyName)
            obj.addProperty("middle_name", this.middleName)
            obj.addProperty("nickname", this.nickname)
            obj.addProperty("profile", this.profile)
            obj.addProperty("picture", this.picture)
            obj.addProperty("website", this.website)
            obj.addProperty("gender", this.gender)
            obj.addProperty("zoneinfo", this.zoneinfo)
            obj.addProperty("locale", this.locale)
            obj.addProperty("updated_at", this.updatedTime)
            obj.addProperty("birthdate", this.birthdate)

            obj.addProperty("email", this.email)
            obj.addProperty("email_verified", this.emailVerified)

            obj.addProperty("phone_number", this.phoneNumber)
            obj.addProperty("phone_number_verified", this.phoneNumberVerified)

            if (this.address != null) {
                val addr = JsonObject()
                addr.addProperty("formatted", address!!.formatted)
                addr.addProperty("street_address", address!!.streetAddress)
                addr.addProperty("locality", address!!.locality)
                addr.addProperty("region", address!!.region)
                addr.addProperty("postal_code", address!!.postalCode)
                addr.addProperty("country", address!!.country)

                obj.add("address", addr)
            }

            return obj
        } else {
            return source
        }
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
    private fun readObject(`in`: ObjectInputStream) {
        `in`.defaultReadObject()
        val o = `in`.readObject()
        if (o != null) {
            val parser = JsonParser()
            source = parser.parse(o as String).asJsonObject
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
         * @param o
         * @return
         */
        @JvmStatic
        fun fromJson(obj: JsonObject): UserInfo {
            val ui = DefaultUserInfo()
            ui.source = obj

            ui.sub = nullSafeGetString(obj, "sub")

            ui.name = nullSafeGetString(obj, "name")
            ui.preferredUsername = nullSafeGetString(obj, "preferred_username")
            ui.givenName = nullSafeGetString(obj, "given_name")
            ui.familyName = nullSafeGetString(obj, "family_name")
            ui.middleName = nullSafeGetString(obj, "middle_name")
            ui.nickname = nullSafeGetString(obj, "nickname")
            ui.profile = nullSafeGetString(obj, "profile")
            ui.picture = nullSafeGetString(obj, "picture")
            ui.website = nullSafeGetString(obj, "website")
            ui.gender = nullSafeGetString(obj, "gender")
            ui.zoneinfo = nullSafeGetString(obj, "zoneinfo")
            ui.locale = nullSafeGetString(obj, "locale")
            ui.updatedTime = nullSafeGetString(obj, "updated_at")
            ui.birthdate = nullSafeGetString(obj, "birthdate")

            ui.email = nullSafeGetString(obj, "email")
            ui.emailVerified =
                if (obj.has("email_verified") && obj["email_verified"].isJsonPrimitive) obj["email_verified"].asBoolean else null

            ui.phoneNumber = nullSafeGetString(obj, "phone_number")
            ui.phoneNumberVerified =
                if (obj.has("phone_number_verified") && obj["phone_number_verified"].isJsonPrimitive) obj["phone_number_verified"].asBoolean else null

            if (obj.has("address") && obj["address"].isJsonObject) {
                val addr = obj["address"].asJsonObject
                ui.address = DefaultAddress()

                ui.address!!.formatted = nullSafeGetString(addr, "formatted")
                ui.address!!.streetAddress = nullSafeGetString(addr, "street_address")
                ui.address!!.locality = nullSafeGetString(addr, "locality")
                ui.address!!.region = nullSafeGetString(addr, "region")
                ui.address!!.postalCode = nullSafeGetString(addr, "postal_code")
                ui.address!!.country = nullSafeGetString(addr, "country")
            }


            return ui
        }

        private fun nullSafeGetString(obj: JsonObject, field: String): String? {
            return if (obj.has(field) && obj[field].isJsonPrimitive) obj[field].asString else null
        }
    }
}
