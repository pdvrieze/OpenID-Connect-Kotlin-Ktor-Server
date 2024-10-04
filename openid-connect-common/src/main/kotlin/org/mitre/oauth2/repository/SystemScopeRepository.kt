package org.mitre.oauth2.repository

import org.mitre.oauth2.model.SystemScope

/**
 * @author jricher
 */
interface SystemScopeRepository {
	val all: Set<SystemScope>

    fun getById(id: Long): SystemScope?

    fun getByValue(value: String): SystemScope?

    fun remove(scope: SystemScope)

    fun save(scope: SystemScope): SystemScope?
}
