package org.mitre.oauth2.repository.ktor

import org.mitre.oauth2.repository.AuthorizationCodeRepository

interface KtorAuthorizationCodeRepository : AuthorizationCodeRepository {
    // Integrated function that clears all expired codes in the database directly.
    fun clearExpiredCodes()
}
