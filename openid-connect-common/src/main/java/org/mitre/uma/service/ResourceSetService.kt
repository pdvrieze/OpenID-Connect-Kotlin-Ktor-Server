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
package org.mitre.uma.service

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.uma.model.ResourceSet

/**
 *
 * Manage registered resource sets at this authorization server.
 *
 * @author jricher
 */
interface ResourceSetService {
    fun saveNew(rs: ResourceSet?): ResourceSet?

    fun getById(id: Long?): ResourceSet?

    fun update(oldRs: ResourceSet?, newRs: ResourceSet?): ResourceSet?

    fun remove(rs: ResourceSet?)

    fun getAllForOwner(owner: String?): Collection<ResourceSet?>?

    fun getAllForOwnerAndClient(owner: String?, authClientId: String?): Collection<ResourceSet?>?

    fun getAllForClient(client: ClientDetailsEntity?): Collection<ResourceSet?>?
}
