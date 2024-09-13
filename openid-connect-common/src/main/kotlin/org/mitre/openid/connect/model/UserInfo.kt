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

import kotlinx.serialization.json.JsonObject
import java.io.Serializable

interface UserInfo : Serializable {
    /**
     * The userId
     */
    var subject: String

    /**
     * The preferred username
     */
    var preferredUsername: String?

    var name: String?

    /**
     * Tthe givenName
     */
    var givenName: String?

    /**
     * The familyName
     */
    var familyName: String?

    /**
     * The middleName
     */
    var middleName: String?

    /**
     * The nickname
     */
    var nickname: String?

    /**
     * The profile
     */
    var profile: String?

    /**
     * The picture
     */
    var picture: String?

    var website: String?

    var email: String?

    var emailVerified: Boolean?

    var gender: String?

    var zoneinfo: String?

    var locale: String?

    var phoneNumber: String?

    var phoneNumberVerified: Boolean?

    var address: Address?

    var updatedTime: String?

    var birthdate: String?

    fun toJson(): JsonObject

    val source: JsonObject?
}
