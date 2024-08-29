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
package org.mitre.openid.connect

import kotlinx.serialization.json.Json
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.util.getLogger


/**
 * Utility class to handle the parsing and serialization of ClientDetails objects.
 *
 * @author jricher
 */
object ClientDetailsEntityJsonProcessor {
    private val logger = getLogger()

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Create an unbound ClientDetailsEntity from the given JSON string.
     *
     * @return the entity if successful, null otherwise
     */
    fun parse(jsonString: String): ClientDetailsEntity {
        return json.decodeFromString<ClientDetailsEntity>(jsonString)
    }

    /**
     * Parse the JSON as a RegisteredClient (useful in the dynamic client filter)
     */
    fun parseRegistered(jsonString: String): RegisteredClient {
        return json.decodeFromString(jsonString)
    }

}
