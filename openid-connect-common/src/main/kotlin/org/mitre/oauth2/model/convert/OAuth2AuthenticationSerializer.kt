package org.mitre.oauth2.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.OAuth2Request



object OAuth2AuthenticationSerializer : KSerializer<OAuth2Authentication> {
    private val oAuth2RequestSerializer: KSerializer<OAuth2Request> = OAuth2RequestSerializer
    private val savedUserAuthenticationSerializer: KSerializer<Authentication> = AuthenticationSerializer

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("org.springframework.security.oauth2.provider.OAuth2Authentication") {
        element("clientAuthorization", oAuth2RequestSerializer.descriptor)
        element("savedUserAuthentication", savedUserAuthenticationSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: OAuth2Authentication) {
        encoder.encodeStructure(descriptor) {
            encodeNullableSerializableElement(descriptor, 0, oAuth2RequestSerializer, value.oAuth2Request)
            encodeNullableSerializableElement(descriptor, 1, savedUserAuthenticationSerializer, value.userAuthentication)
        }
    }

    override fun deserialize(decoder: Decoder): OAuth2Authentication {
        var storedRequest: OAuth2Request? = null
        var userAuthentication: Authentication? = null
        decoder.decodeStructure(descriptor) {
            while (true) {
                when (val i = decodeElementIndex(descriptor)) {
                    0 -> storedRequest = decodeNullableSerializableElement(descriptor, i, oAuth2RequestSerializer, storedRequest)
                    1 -> userAuthentication = decodeNullableSerializableElement(descriptor, i, savedUserAuthenticationSerializer, userAuthentication)
                    CompositeDecoder.DECODE_DONE -> break
                    else -> error("Can not deserialize value")
                }
            }
        }

        return OAuth2Authentication(storedRequest, userAuthentication)
    }
}

typealias KXS_OAuth2Authentication = @Serializable(OAuth2AuthenticationSerializer::class) OAuth2Authentication
