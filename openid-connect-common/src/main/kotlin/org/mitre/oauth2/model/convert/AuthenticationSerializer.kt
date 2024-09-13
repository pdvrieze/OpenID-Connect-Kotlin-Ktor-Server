package org.mitre.oauth2.model.convert

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.SavedUserAuthentication

object AuthenticationSerializer : KSerializer<Authentication> {
    private val delegate = SerialDelegate.serializer()

    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor(" org.springframework.security.core.Authentication", delegate.descriptor)

    override fun serialize(encoder: Encoder, value: Authentication) {
        delegate.serialize(encoder, SerialDelegate(value))
    }

    override fun deserialize(decoder: Decoder): Authentication {
        return delegate.deserialize(decoder).toAuthentication()
    }

    @Serializable
    private class SerialDelegate(
        val name: String,
        val sourceClass: String? = null,
        @EncodeDefault val authenticated: Boolean = false,
        val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority> = emptySet(),
    ) {
        constructor(e: Authentication) : this(
            name = e.name,
            sourceClass = when (e) {
                is SavedUserAuthentication -> e.sourceClass
                else -> e.javaClass.name
            },
            authenticated = e.isAuthenticated,
            authorities = e.authorities.toSet(),
        )

        fun toAuthentication(): SavedUserAuthentication {
            return SavedUserAuthentication(
                name = name,
                id = null,
                authorities = authorities,
                authenticated = authenticated,
                sourceClass = sourceClass
            )
        }
    }
}

typealias KXS_Authentication = @Serializable(AuthenticationSerializer::class) Authentication
