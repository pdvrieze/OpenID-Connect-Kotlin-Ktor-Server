package org.mitre.oauth2.service

import org.mitre.oauth2.model.SystemScope

/**
 * @author jricher
 */
interface SystemScopeService {
    val all: Set<SystemScope>

    /**
     * Get all scopes that are defaulted to new clients on this system
     */
    val defaults: Set<SystemScope>

    /**
     * Get all the reserved system scopes. These can't be used
     * by clients directly, but are instead tied to special system
     * tokens like id tokens and registration access tokens.
     *
     */
    val reserved: Set<SystemScope>

    /**
     * Get all the registered scopes that are restricted.
     */
    val restricted: Set<SystemScope>

    /**
     * Get all the registered scopes that aren't restricted.
     */
    val unrestricted: Set<SystemScope>

    fun getById(id: Long): SystemScope?

    fun getByValue(value: String): SystemScope?

    fun remove(scope: SystemScope)

    fun save(scope: SystemScope): SystemScope?

    /**
     * Translate the set of scope strings into a set of SystemScope objects.
     */
    fun fromStrings(scope: Set<String>?): Set<SystemScope>?

    /**
     * Pluck the scope values from the set of SystemScope objects and return a list of strings
     */
    fun toStrings(scope: Set<SystemScope>?): Set<String>?

    /**
     * Test whether the scopes in both sets are compatible. All scopes in "actual" must exist in "expected".
     */
    fun scopesMatch(expected: Set<String>?, actual: Set<String>?): Boolean

    /**
     * Remove any system-reserved or registered restricted scopes from the
     * set and return the result.
     */
    fun removeRestrictedAndReservedScopes(scopes: Set<SystemScope>?): Set<SystemScope>?

    /**
     * Remove any system-reserved scopes from the set and return the result.
     */
    fun removeReservedScopes(scopes: Set<SystemScope>?): Set<SystemScope>?

    companion object {
        const val OFFLINE_ACCESS: String = "offline_access"
        const val OPENID_SCOPE: String = "openid"
        const val REGISTRATION_TOKEN_SCOPE: String =
            "registration-token" // this scope manages dynamic client registrations
        const val RESOURCE_TOKEN_SCOPE: String = "resource-token" // this scope manages client-style protected resources
        const val UMA_PROTECTION_SCOPE: String = "uma_protection"
        const val UMA_AUTHORIZATION_SCOPE: String = "uma_authorization"

        val reservedScopes: Set<SystemScope> = hashSetOf(
            SystemScope(REGISTRATION_TOKEN_SCOPE),
            SystemScope(RESOURCE_TOKEN_SCOPE)
        )
    }
}
