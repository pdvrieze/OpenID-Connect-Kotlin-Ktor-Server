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

/**
 * @property formatted The formatted address string
 */
@Serializable
data class DefaultAddress(
    override var id: Long? = null,
    override var formatted: String? = null,

    @SerialName("street_address")
    override var streetAddress: String? = null,
    override var locality: String? = null,
    override var region: String? = null,

    @SerialName("postal_code")
    override var postalCode: String? = null,
    override var country: String? = null,
) : Address {

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
}
