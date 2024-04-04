package org.mitre.oauth2.model.convert

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.provider.OAuth2Request

object OAuth2RequestSerializer: KSerializer<OAuth2Request> {

    @Serializable
    private class SerialDelegate(
        val scope: Set<String>? = null,
        val resourceIds: Set<String>? = null,
        val approved: Boolean = false,
        val denied: Boolean? = null,
        val authorities: Set<GrantedAuthority>? = null,
        val authorizationParameters: Map<String, String> = emptyMap(),
        val responseTypes: Set<String>? = null,
        val redirectUri: String? = null,
        val clientId: String? = null,
        val approvalParameters: JsonElement? = null,
        val extensionStrings: Map<String, String>? = null
    ) {
        constructor(b: OAuth2Request): this(
            scope = b.scope,
            resourceIds= b.resourceIds,
            approved= b.isApproved,
            authorities= b.authorities.toHashSet(),
            authorizationParameters= b.requestParameters,
            responseTypes= b.responseTypes,
            redirectUri= b.redirectUri,
            clientId= b.clientId,
            extensionStrings = b.extensions.asSequence().mapNotNull { (k, v) -> (v as? String)?.let { k to v } }
                .associate { it }
        )

        fun toOAuthRequest(): OAuth2Request {
            val approved = when {
                approved -> true
                denied == null -> approved
                else -> !denied
            }
            return OAuth2Request(authorizationParameters, clientId, authorities, approved, scope, resourceIds, redirectUri, responseTypes, extensionStrings)
        }
    }

    private val delegate = SerialDelegate.serializer()
    override val descriptor: SerialDescriptor = SerialDescriptor("OAuth2Request", delegate.descriptor)

    override fun serialize(encoder: Encoder, value: OAuth2Request) {
        delegate.serialize(encoder, SerialDelegate(value))
    }

    override fun deserialize(decoder: Decoder): OAuth2Request {
        return delegate.deserialize(decoder).toOAuthRequest()
    }
}

typealias KXS_OAuth2Request = @Serializable(OAuth2RequestSerializer::class) OAuth2Request

