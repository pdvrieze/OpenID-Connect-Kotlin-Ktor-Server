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
package org.mitre.openid.connect.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import javax.persistence.Basic
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.Table

@Entity
@Table(name = "address")
@Serializable
class DefaultAddress(
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    @Transient
    override var id: Long? = null,

    /**
     * The formatted address string
     */
    @get:Column(name = "formatted")
    @get:Basic
    override var formatted: String? = null,

    @get:Column(name = "street_address")
    @get:Basic
    @SerialName("street_address")
    override var streetAddress: String? = null,

    @get:Column(name = "locality")
    @get:Basic
    override var locality: String? = null,

    @get:Column(name = "region")
    @get:Basic
    override var region: String? = null,

    @get:Column(name = "postal_code")
    @get:Basic
    @SerialName("postal_code")
    override var postalCode: String? = null,

    @get:Column(name = "country")
    @get:Basic
    override var country: String? = null,
) : Address {
    /**
     * Empty constructor
     */

    /**
     * Copy constructor from an existing address.
     */
    constructor(address: Address) : this(
        formatted = address.formatted,
        streetAddress = address.streetAddress,
        locality = address.locality,
        region = address.region,
        postalCode = address.postalCode,
        country = address.country,
    )

    companion object {
        fun from(address: Address): DefaultAddress {
            return address as? DefaultAddress ?: DefaultAddress(
                id = address.id,
                formatted = address.formatted,
                streetAddress = address.streetAddress,
                locality = address.locality,
                region = address.region,
                postalCode = address.postalCode,
                country = address.country,
            )
        }

        private const val serialVersionUID = -1304880008685206811L
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DefaultAddress

        if (id != other.id) return false
        if (formatted != other.formatted) return false
        if (streetAddress != other.streetAddress) return false
        if (locality != other.locality) return false
        if (region != other.region) return false
        if (postalCode != other.postalCode) return false
        if (country != other.country) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id?.hashCode() ?: 0
        result = 31 * result + (formatted?.hashCode() ?: 0)
        result = 31 * result + (streetAddress?.hashCode() ?: 0)
        result = 31 * result + (locality?.hashCode() ?: 0)
        result = 31 * result + (region?.hashCode() ?: 0)
        result = 31 * result + (postalCode?.hashCode() ?: 0)
        result = 31 * result + (country?.hashCode() ?: 0)
        return result
    }
}
