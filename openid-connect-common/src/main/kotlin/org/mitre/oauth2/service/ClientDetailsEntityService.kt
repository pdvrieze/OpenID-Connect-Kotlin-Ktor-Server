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
package org.mitre.oauth2.service

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails

interface ClientDetailsEntityService {
    fun saveNewClient(client: OAuthClientDetails): OAuthClientDetails

    fun getClientById(id: Long): OAuthClientDetails?

    fun deleteClient(client: OAuthClientDetails)

    fun loadClientByClientId(clientId: String): OAuthClientDetails?

    fun updateClient(oldClient: OAuthClientDetails, newClient: OAuthClientDetails): OAuthClientDetails

    val allClients: Collection<OAuthClientDetails>

    fun generateClientIdString(client: OAuthClientDetails): String

    fun generateClientSecret(client: OAuthClientDetails): String?
}

interface SpringClientDetailsEntityService : ClientDetailsEntityService {

    override fun loadClientByClientId(clientId: String): ClientDetailsEntity?

}
