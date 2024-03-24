/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.model

import com.google.gson.JsonElement
import org.mitre.oauth2.model.convert.JsonElementStringConverter
import javax.persistence.Basic
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.Table

/**
 * @author jricher
 */
@Entity
@Table(name = "claim")
class Claim {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "name")
    @get:Basic
    var name: String? = null

    @get:Column(name = "friendly_name")
    @get:Basic
    var friendlyName: String? = null

    @get:Column(name = "claim_type")
    @get:Basic
    var claimType: String? = null

    @get:Convert(converter = JsonElementStringConverter::class)
    @get:Column(name = "claim_value")
    @get:Basic
    var value: JsonElement? = null

    @get:CollectionTable(name = "claim_token_format", joinColumns = [JoinColumn(name = "owner_id")])
    @get:Column(name = "claim_token_format")
    @get:ElementCollection(fetch = FetchType.EAGER)
    var claimTokenFormat: Set<String>? = null

    @get:CollectionTable(name = "claim_issuer", joinColumns = [JoinColumn(name = "owner_id")])
    @get:Column(name = "issuer")
    @get:ElementCollection(fetch = FetchType.EAGER)
    var issuer: Set<String>? = null

    override fun toString(): String {
        return "Claim [id=$id, name=$name, friendlyName=$friendlyName, claimType=$claimType, value=$value, claimTokenFormat=$claimTokenFormat, issuer=$issuer]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Claim

        if (id != other.id) return false
        if (name != other.name) return false
        if (friendlyName != other.friendlyName) return false
        if (claimType != other.claimType) return false
        if (value != other.value) return false
        if (claimTokenFormat != other.claimTokenFormat) return false
        if (issuer != other.issuer) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id?.hashCode() ?: 0
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (friendlyName?.hashCode() ?: 0)
        result = 31 * result + (claimType?.hashCode() ?: 0)
        result = 31 * result + (value?.hashCode() ?: 0)
        result = 31 * result + (claimTokenFormat?.hashCode() ?: 0)
        result = 31 * result + (issuer?.hashCode() ?: 0)
        return result
    }

}
