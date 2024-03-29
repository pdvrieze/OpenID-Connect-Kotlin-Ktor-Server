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
package org.mitre.openid.connect.service.impl

import org.mitre.openid.connect.model.WhitelistedSite
import org.mitre.openid.connect.repository.WhitelistedSiteRepository
import org.mitre.openid.connect.service.WhitelistedSiteService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * Implementation of the WhitelistedSiteService
 *
 * @author Michael Joseph Walsh, aanganes
 */
@Service
@Transactional(value = "defaultTransactionManager")
class DefaultWhitelistedSiteService : WhitelistedSiteService {
    @Autowired
    private lateinit var repository: WhitelistedSiteRepository

    override fun getById(id: java.lang.Long): WhitelistedSite? {
        return repository.getById(id)
    }

    override fun remove(whitelistedSite: WhitelistedSite) {
        repository.remove(whitelistedSite)
    }

    override fun saveNew(whitelistedSite: WhitelistedSite): WhitelistedSite {
        require(whitelistedSite.id == null) {
            "A new whitelisted site cannot be created with an id value already set: ${whitelistedSite.id}"
        }
        return repository.save(whitelistedSite)
    }

    override val all: Collection<WhitelistedSite>?
        get() = repository.all

    override fun getByClientId(clientId: String): WhitelistedSite? {
        return repository.getByClientId(clientId)
    }

    override fun update(oldWhitelistedSite: WhitelistedSite, whitelistedSite: WhitelistedSite): WhitelistedSite {
        require(!(oldWhitelistedSite == null || whitelistedSite == null)) { "Neither the old or new sites may be null" }
        return repository.update(oldWhitelistedSite, whitelistedSite)
    }
}
