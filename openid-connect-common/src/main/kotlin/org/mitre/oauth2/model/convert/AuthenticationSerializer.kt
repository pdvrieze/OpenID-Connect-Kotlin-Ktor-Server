package org.mitre.oauth2.model.convert

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.SavedAuthentication
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

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
        val authTime: ISOInstant? = null,
        @EncodeDefault val authenticated: Boolean = authTime!=null,
        val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority> = emptySet(),
        val scopes: Set<String> = emptySet(),
    ) {
        constructor(e: Authentication) : this(SavedAuthentication.from(e))

        constructor(s: SavedAuthentication) : this(
            s.principalName,
            s.sourceClass,
            authTime = s.authTime,
            authorities = s.authorities
        )

        fun toAuthentication(): SavedAuthentication {
            return SavedAuthentication(
                principalName = name,
                id = null,
                authTime = authTime ?: Instant.EPOCH,
                authorities = authorities,
                scope = scopes,
                sourceClass = sourceClass,
            )
        }
    }
}

typealias KXS_Authentication = @Serializable(AuthenticationSerializer::class) OldAuthentication
