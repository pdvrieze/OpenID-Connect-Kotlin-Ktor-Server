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

import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository
import org.mitre.oauth2.service.SystemScopeService
import org.mitre.oauth2.service.SystemScopeService.Companion.reservedScopes

/**
 * @author jricher
 */
class DefaultSystemScopeService : SystemScopeService {
    private lateinit var repository: SystemScopeRepository

    @Deprecated("Use version taking a system scope repository")
    constructor()

    constructor(repository: SystemScopeRepository) {
        this.repository = repository
    }

    private val isDefault: (SystemScope?) -> Boolean = { input -> input != null && input.isDefaultScope }

    private val isRestricted: (SystemScope?) -> Boolean = { input -> input != null && input.isRestricted }

    private val isReserved: (SystemScope?) -> Boolean = { input -> input != null && input in reserved }

    private val stringToSystemScope: (String?) -> SystemScope? = { input ->
        when {
            input.isNullOrEmpty() -> null

            // get the real scope if it's available,make a fake one otherwise
            else -> getByValue(input) ?: SystemScope(input)
        }
    }

    private val systemScopeToString: (SystemScope?) -> String? = { input -> input?.value }

    override val all: Set<SystemScope>
        /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#getAll()
	 */
        get() = repository.all

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#getById(java.lang.Long)
	 */
    override fun getById(id: Long): SystemScope? {
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
        isReserved(scope) -> null
        else -> repository.save(scope)
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#fromStrings(java.util.Set)
	 */
    override fun fromStrings(scope: Set<String>?): Set<SystemScope> {
        return when (scope) {
            null -> emptySet()
            else -> scope.mapNotNullTo(mutableSetOf(), stringToSystemScope)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#toStrings(java.util.Set)
	 */
    override fun toStrings(scope: Set<SystemScope>?): Set<String> {
        return when (scope) {
            null -> emptySet()
            else -> scope.mapNotNullTo(mutableSetOf(), systemScopeToString)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.service.SystemScopeService#scopesMatch(java.util.Set, java.util.Set)
	 */
    override fun scopesMatch(expected: Set<String>?, actual: Set<String>): Boolean {
        val ex = fromStrings(expected) ?: return false
        val act = fromStrings(actual) ?: return false

        return act.all { it in ex }
    }

    override val defaults: Set<SystemScope>
        get() = all.filterTo(HashSet(), isDefault)


    override val reserved: Set<SystemScope>
        get() = reservedScopes

    override val restricted: Set<SystemScope>
        get() = all.filterTo(mutableSetOf(), isRestricted)

    override val unrestricted: Set<SystemScope>
        get() = all.filterNotTo(mutableSetOf(), isRestricted)

    override fun removeRestrictedAndReservedScopes(scopes: Set<SystemScope>): Set<SystemScope> {
        return scopes.filterNotTo(mutableSetOf()) {
            it.isRestricted || it in reserved
        }
    }

    override fun removeReservedScopes(scopes: Set<SystemScope>): Set<SystemScope> {
        return scopes.filterNotTo(hashSetOf(), isReserved)
    }
}
