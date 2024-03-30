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
package org.mitre.openid.connect.service.impl

import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.service.ResourceSetService
import org.springframework.stereotype.Service
import java.lang.Long

/**
 * Dummy resource set service that doesn't do anything; acts as a stub for the
 * introspection service when the UMA functionality is disabled.
 *
 * @author jricher
 */
@Service
class DummyResourceSetService : ResourceSetService {
    override fun saveNew(rs: ResourceSet): ResourceSet {
        throw UnsupportedOperationException()
    }

    override fun getById(id: Long): Nothing {
        throw UnsupportedOperationException()
    }

    override fun update(oldRs: ResourceSet, newRs: ResourceSet): ResourceSet {
        throw UnsupportedOperationException()
    }

    override fun remove(rs: ResourceSet?) {
        throw UnsupportedOperationException()
    }

    override fun getAllForOwner(owner: String?): Nothing {
        throw UnsupportedOperationException()
    }

    override fun getAllForOwnerAndClient(owner: String?, authClientId: String?): Collection<ResourceSet> {
        return emptySet()
    }

    override fun getAllForClient(client: ClientDetailsEntity?): Collection<ResourceSet> {
        return emptySet()
    }
}
