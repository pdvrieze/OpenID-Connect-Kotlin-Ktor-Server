package org.mitre.web

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.UserAuthentication
import io.ktor.server.auth.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.openid.connect.filter.NormalizedResponseType
import org.mitre.openid.connect.request.Prompt
import java.time.Instant

@Serializable
data class OpenIdSessionStorage(
    val authorizationRequest: AuthorizationRequest? = null,
    val principal: UserAuthentication? = null,
    val redirectUri: String? = null,
    val state: String? = null,
    val loginHint: String? = null,
    val responseType: NormalizedResponseType? = null,
    val pendingPrompts: Set<Prompt>? = null,
) {

    constructor() : this(principal = null)

    init {
        if (principal != null) {
            requireNotNull(authTime) { "Missing authorization time in session principal" }
        } else {
            require(authTime == null) { "Authorization time set, but no principal" }
        }
    }

    val authTime: Instant? get() = principal?.authTime

    companion object {
        val COOKIE_NAME: String = "_openid_session"
    }
}

object UserIdPrincipalSerializer: KSerializer<UserIdPrincipal> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("io.ktor.server.auth.UserIdPrincipal", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): UserIdPrincipal {
        return UserIdPrincipal(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: UserIdPrincipal) {
        encoder.encodeString(value.name)
    }
}
