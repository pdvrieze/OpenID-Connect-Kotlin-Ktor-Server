package org.mitre.oauth2.model

import java.time.Instant

interface OAuth2RefreshToken {
    val value: String
    val expirationInstant: Instant
}
