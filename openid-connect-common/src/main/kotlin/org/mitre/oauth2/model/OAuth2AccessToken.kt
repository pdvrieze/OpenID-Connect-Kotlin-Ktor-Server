package org.mitre.oauth2.model

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*


interface OAuth2AccessToken {
    val scope: Set<String>
    val refreshToken: OAuth2RefreshToken?
    val tokenType: String
    val isExpired: Boolean
    @Deprecated("Use expirationInstant")
    val expiration: Date get() = Date.from(expirationInstant)
    val expirationInstant: Instant
    val expiresIn: Int
        get() {
            return Instant.now().until(expirationInstant, ChronoUnit.SECONDS).toInt().coerceAtLeast(0)
        }
    val value: String

    companion object {
        val BEARER_TYPE = "Bearer"
        val OAUTH2_TYPE = "OAuth2"
    }
}

