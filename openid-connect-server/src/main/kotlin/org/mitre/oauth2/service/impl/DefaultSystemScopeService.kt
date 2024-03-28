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
package org.mitre.oauth2.service.impl

import com.google.common.base.Function
import com.google.common.base.Predicate
import com.google.common.base.Predicates
import com.google.common.collect.Collections2
import com.google.common.collect.Sets
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.SystemScopeService.Companion.reservedScopes
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

/**
 * @author jricher
 */
@Service("defaultSystemScopeService")
class DefaultSystemScopeService : SystemScopeService {
    @Autowired
    private lateinit var repository: SystemScopeRepository

    private val isDefault: Predicate<SystemScope> = Predicate { input -> input != null && input.isDefaultScope }

    private val isRestricted: Predicate<SystemScope> = Predicate { input -> input != null && input.isRestricted }

    private val isReserved: Predicate<SystemScope> = Predicate { input -> input != null && reserved.contains(input) }

    private val stringToSystemScope: Function<String, SystemScope> = object : Function<String, SystemScope> {
        override fun apply(input: String?): SystemScope? {
            if (input.isNullOrEmpty()) return null

            // get the real scope if it's available,make a fake one otherwise
            return getByValue(input) ?: SystemScope(input)
        }
    }

    private val systemScopeToString: Function<SystemScope, String> = object : Function<SystemScope, String> {
        override fun apply(input: SystemScope?): String? {
            return input?.value
        }
    }

    override val all: Set<SystemScope>
        /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#getAll()
	 */
        get() = repository.all

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#getById(java.lang.Long)
	 */
    override fun getById(id: java.lang.Long): SystemScope? {
        return repository.getById(id)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#getByValue(java.lang.String)
	 */
    override fun getByValue(value: String): SystemScope? {
        return repository.getByValue(value)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#remove(org.mitre.oauth2.model.SystemScope)
	 */
    override fun remove(scope: SystemScope) {
        repository.remove(scope)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#save(org.mitre.oauth2.model.SystemScope)
	 */
    override fun save(scope: SystemScope): SystemScope? = when {
        // don't allow saving of reserved scopes
        isReserved.apply(scope) -> null
        else -> repository.save(scope)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#fromStrings(java.util.Set)
	 */
    override fun fromStrings(scope: Set<String>?): Set<SystemScope>? {
        return if (scope == null) {
            null
        } else {
            LinkedHashSet(Collections2.filter(Collections2.transform(scope, stringToSystemScope), Predicates.notNull()))
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#toStrings(java.util.Set)
	 */
    override fun toStrings(scope: Set<SystemScope>?): Set<String>? {
        return if (scope == null) {
            null
        } else {
            LinkedHashSet(Collections2.filter(Collections2.transform(scope, systemScopeToString), Predicates.notNull()))
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#scopesMatch(java.util.Set, java.util.Set)
	 */
    override fun scopesMatch(expected: Set<String>?, actual: Set<String>): Boolean {
        val ex = fromStrings(expected) ?: return false
        val act = fromStrings(actual) ?: return false

        for (actScope in act) {
            // first check to see if there's an exact match
            if (actScope !in ex) {
                return false
            }
            // if we did find an exact match, we need to check the rest
        }

        // if we got all the way down here, the setup passed
        return true
    }

    override val defaults: Set<SystemScope>
        get() = Sets.filter(all, isDefault)


    override val reserved: Set<SystemScope>
        get() = reservedScopes

    override val restricted: Set<SystemScope>
        get() = Sets.filter(all, isRestricted)

    override val unrestricted: Set<SystemScope>
        get() = Sets.filter(all, Predicates.not(isRestricted))

    override fun removeRestrictedAndReservedScopes(scopes: Set<SystemScope>): Set<SystemScope> {
        return Sets.filter(scopes, Predicates.not(Predicates.or(isRestricted, isReserved)))
    }

    override fun removeReservedScopes(scopes: Set<SystemScope>): Set<SystemScope> {
        return Sets.filter(scopes, Predicates.not(isReserved))
    }
}
