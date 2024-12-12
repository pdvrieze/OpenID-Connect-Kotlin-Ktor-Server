package org.mitre.oauth2.introspectingfilter

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.EpochInstant

@Serializable
data class IntrospectionResponse(
    val active: Boolean,
    @SerialName("scope")
    val scopeString: String? = null,
    @SerialName("client_id")
    val clientId: String? = null,
    val username: String? = null,
    @SerialName("token_type")
    val tokenType: String? = null,
    @SerialName("exp")
    val expiration: EpochInstant? = null,
    @SerialName("iat")
    val issuedAt: EpochInstant? = null,
    @SerialName("nbf")
    val notBefore: EpochInstant? = null,
    @SerialName("sub")
    val subject: String? = null,
    @SerialName("aud")
    val audience: String? = null,
    @SerialName("iss")
    val issuer: String? = null,
    @SerialName("jti")
    val jwtId: String? = null,
) {
    val scopes get(): Set<String> = scopeString?.splitToSequence(' ')
        ?.filterNot { it.isBlank() }
        ?.toCollection(HashSet()) ?: emptySet()
}
