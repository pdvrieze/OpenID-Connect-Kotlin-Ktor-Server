package org.mitre.oauth2.model

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(GrantedAuthority.Companion::class)
interface GrantedAuthority {

    val authority: String

    companion object: KSerializer<GrantedAuthority> {
        val ROLE_API: LocalGrantedAuthority = LocalGrantedAuthority("ROLE_API")
        val ROLE_EXTERNAL_USER: LocalGrantedAuthority = LocalGrantedAuthority("ROLE_EXTERNAL_USER")
        val ROLE_ADMIN: LocalGrantedAuthority = LocalGrantedAuthority("ROLE_ADMIN")
        val ROLE_CLIENT: LocalGrantedAuthority = LocalGrantedAuthority("ROLE_CLIENT")
        val ROLE_USER: LocalGrantedAuthority = LocalGrantedAuthority("ROLE_USER")

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("org.mitre.oauth2.model.GrantedAuthority", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: GrantedAuthority) {
            encoder.encodeString(value.authority)
        }

        override fun deserialize(decoder: Decoder): GrantedAuthority {
            return when(val s = decoder.decodeString()) {
                "ROLE_EXTERNAL_USER" -> ROLE_EXTERNAL_USER
                "ROLE_ADMIN" -> ROLE_ADMIN
                "ROLE_CLIENT" -> ROLE_CLIENT
                "ROLE_USER" -> ROLE_USER
                else -> LocalGrantedAuthority(s)
            }
        }


        operator fun invoke(a: String): LocalGrantedAuthority = LocalGrantedAuthority(a)
    }
}

@JvmInline
@Serializable
value class LocalGrantedAuthority(override val authority: String): GrantedAuthority

@JvmInline
value class ScopeAuthority(val scope: String): GrantedAuthority {
    override val authority: String get() = "OAUTH_SCOPE_$scope"
}
