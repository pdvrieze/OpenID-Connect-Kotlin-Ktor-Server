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

import org.mitre.openid.connect.model.BlacklistedSite
import org.mitre.openid.connect.repository.BlacklistedSiteRepository
import org.mitre.openid.connect.service.BlacklistedSiteService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * @author jricher
 */
@Service
@Transactional(value = "defaultTransactionManager")
class DefaultBlacklistedSiteService : BlacklistedSiteService {
    @Autowired
    private lateinit var repository: BlacklistedSiteRepository

    @Deprecated("JPA only")
    constructor()

    constructor(repository: BlacklistedSiteRepository) { this.repository = repository }

    override val all: Collection<BlacklistedSite>
        /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#getAll()
	 */
        get() = repository.all

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#getById(java.lang.Long)
	 */
    override fun getById(id: Long): BlacklistedSite? {
        return repository.getById(id)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#remove(org.mitre.openid.connect.model.BlacklistedSite)
	 */
    override fun remove(blacklistedSite: BlacklistedSite) {
        repository.remove(blacklistedSite)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#saveNew(org.mitre.openid.connect.model.BlacklistedSite)
	 */
    override fun saveNew(blacklistedSite: BlacklistedSite): BlacklistedSite {
        return repository.save(blacklistedSite)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#update(org.mitre.openid.connect.model.BlacklistedSite, org.mitre.openid.connect.model.BlacklistedSite)
	 */
    override fun update(oldBlacklistedSite: BlacklistedSite, blacklistedSite: BlacklistedSite): BlacklistedSite {
        return repository.update(oldBlacklistedSite, blacklistedSite)
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.service.BlacklistedSiteService#isBlacklisted(java.lang.String)
	 */
    override fun isBlacklisted(uri: String): Boolean {
        if (uri.isNullOrEmpty()) {
            return false // can't be blacklisted if you don't exist
        }

        val sites = all

        // TODO: rewrite this to do regex matching and use the Guava predicates collection
        for (blacklistedSite in sites) {
            if ((blacklistedSite.uri ?: "") == uri) {
                return true
            }
        }

        return false
    }
}
