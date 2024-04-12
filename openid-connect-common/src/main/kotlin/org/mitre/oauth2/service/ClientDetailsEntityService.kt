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
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.ClientDetailsService

interface ClientDetailsEntityService : ClientDetailsService {
    fun saveNewClient(client: ClientDetailsEntity): ClientDetailsEntity?

    fun getClientById(id: Long): ClientDetailsEntity?

    @Throws(OAuth2Exception::class)
    override fun loadClientByClientId(clientId: String): ClientDetailsEntity?

    fun deleteClient(client: ClientDetailsEntity)

    fun updateClient(oldClient: ClientDetailsEntity, newClient: ClientDetailsEntity): ClientDetailsEntity

    val allClients: Collection<ClientDetailsEntity>

    fun generateClientId(client: ClientDetailsEntity): ClientDetailsEntity

    fun generateClientSecret(client: ClientDetailsEntity): ClientDetailsEntity
}
