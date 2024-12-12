package org.mitre.oauth2.model.convert

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.SavedAuthentication
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.OldAuthentication
import org.mitre.oauth2.model.OldSavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest


object AuthenticatedAuthorizationRequestSerializer : KSerializer<AuthenticatedAuthorizationRequest> {
    private val authorizationRequestSerializer: KSerializer<AuthorizationRequest> = AuthorizationRequest.serializer()
    private val savedUserAuthenticationSerializer: KSerializer<Authentication> = AuthenticationSerializer

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("org.springframework.security.oauth2.provider.OAuth2Authentication") {
        element("clientAuthorization", authorizationRequestSerializer.descriptor)
        element("savedUserAuthentication", savedUserAuthenticationSerializer.descriptor)
    }

    override fun serialize(encoder: Encoder, value: AuthenticatedAuthorizationRequest) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, authorizationRequestSerializer.nullable, value.authorizationRequest)
            encodeSerializableElement(descriptor, 1, savedUserAuthenticationSerializer.nullable, value.userAuthentication)
        }
    }

    override fun deserialize(decoder: Decoder): AuthenticatedAuthorizationRequest {
        return decoder.decodeStructure(descriptor) {
            var storedRequest: AuthorizationRequest? = null
            var userAuthentication: SavedAuthentication? = null
            while (true) {
                when (val i = decodeElementIndex(descriptor)) {
                    0 -> storedRequest = decodeSerializableElement(descriptor, i, authorizationRequestSerializer, storedRequest)

                    1 -> userAuthentication =
                        decodeSerializableElement(descriptor, i, savedUserAuthenticationSerializer, userAuthentication) as SavedAuthentication
                    CompositeDecoder.DECODE_DONE -> break

                    else -> error("Can not deserialize value")
                }
            }
            requireNotNull(storedRequest)
            AuthenticatedAuthorizationRequest(storedRequest, userAuthentication)
        }
    }

}

