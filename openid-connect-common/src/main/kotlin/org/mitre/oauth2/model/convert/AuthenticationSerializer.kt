package org.mitre.oauth2.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.SavedUserAuthentication
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority

object AuthenticationSerializer : KSerializer<Authentication> {
    private val delegate = SerialDelegate.serializer()

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
        val name: String? = null,
        val sourceClass: String? = null,
        val authenticated: Boolean = false,
        val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority>? = null,
    ) {
        constructor(e: Authentication) : this(
            name = e.name,
            sourceClass = (e as? SavedUserAuthentication)?.sourceClass ?: e.javaClass.name,
            authenticated = e.isAuthenticated,
            authorities = e.authorities?.toSet(),
        )

        fun toAuthentication(): SavedUserAuthentication {
            return SavedUserAuthentication().also { r ->
                name?.let { r.setName(it) }
                sourceClass?.let { r.setName(it) }
                r.isAuthenticated = authenticated
                authorities?.let { r.authorities = it }
            }
        }
    }
}

typealias KXS_Authentication = @Serializable(AuthenticationSerializer::class) Authentication
