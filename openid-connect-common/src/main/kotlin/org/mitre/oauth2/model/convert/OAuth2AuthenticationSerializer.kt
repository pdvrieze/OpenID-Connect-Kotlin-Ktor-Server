package org.mitre.oauth2.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import org.mitre.oauth2.model.OAuth2Authentication


object OAuth2AuthenticationSerializer : KSerializer<OAuth2Authentication> {
    private val oAuth2RequestSerializer: KSerializer<OAuth2Request> = OAuth2RequestSerializer
    private val savedUserAuthenticationSerializer: KSerializer<Authentication> = AuthenticationSerializer

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("org.springframework.security.oauth2.provider.OAuth2Authentication") {
        element("clientAuthorization", oAuth2RequestSerializer.descriptor)
        element("savedUserAuthentication", savedUserAuthenticationSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: OAuth2Authentication) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, oAuth2RequestSerializer.nullable, value.oAuth2Request)
            encodeSerializableElement(descriptor, 1, savedUserAuthenticationSerializer.nullable, value.userAuthentication)
        }
    }

    override fun deserialize(decoder: Decoder): OAuth2Authentication {
        return decoder.decodeStructure(descriptor) {
            var storedRequest: OAuth2Request? = null
            var userAuthentication: Authentication? = null
            while (true) {
                when (val i = decodeElementIndex(descriptor)) {
                    0 -> storedRequest = decodeSerializableElement(descriptor, i, oAuth2RequestSerializer, storedRequest)
                    1 -> userAuthentication = decodeSerializableElement(descriptor, i, savedUserAuthenticationSerializer, userAuthentication)
                    CompositeDecoder.DECODE_DONE -> break
                    else -> error("Can not deserialize value")
                }
            }
            OAuth2Authentication(storedRequest, userAuthentication)
        }
    }

}

typealias KXS_OAuth2Authentication = @Serializable(OAuth2AuthenticationSerializer::class) OAuth2Authentication
