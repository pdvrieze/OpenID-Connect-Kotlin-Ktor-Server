package org.mitre.oauth2.model.request

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

@Serializable(AuthorizationRequest.Companion::class)
interface AuthorizationRequest {
    @SerialName("authorizationParameters")
    @InternalForStorage
    val requestParameters: Map<String, String>
    val clientId: String
    val authorities: Set<GrantedAuthority>

    @SerialName("approved")
    val isApproved: Boolean get() = approval != null
    val approval: Approval?
    val scope: Set<String>
    val resourceIds: Set<String>?
    val redirectUri: String?
    val responseTypes: Set<String>?
    val state: String?
    val requestTime: ISOInstant?
    /** Code challenge from PKCE (RFC7636) */
    val codeChallenge: CodeChallenge?

    @SerialName("extensionStrings")
    val denied: Boolean get() = ! isApproved

    // Extensions string function as to store in an auth holder
    @InternalForStorage
    val authHolderExtensions: Map<String, String>

    fun builder(): Builder

    @Serializable
    class Approval(val approvedSiteId: Long? = null, val approvalTime: ISOInstant) {
        constructor(approvalTime: ISOInstant) : this(approvedSiteId = null, approvalTime)
        constructor(approvedSite: ApprovedSite?, approvalTime: ISOInstant) : this(approvedSite?.id, approvalTime)
    }

    @Serializable
    private class SerialDelegate private constructor(
        @SerialName("authorizationParameters")
        val requestParameters: Map<String, String> = emptyMap(),
        val clientId: String,
        val authorities: Set<GrantedAuthority> = emptySet(),
        @SerialName("approved")
        val isApproved: Boolean = false,
        val scope: Set<String> = emptySet(),
        val resourceIds: Set<String>? = null,
        val redirectUri: String? = null,
        val responseTypes: Set<String>? = null,
        val state: String? = null,
        val requestTime: ISOInstant? = null,
        @SerialName("extensionStrings")
        @property:InternalForStorage
        val extensions: Map<String, String>? = null,
    ) {

        @OptIn(InternalForStorage::class)
        fun toAuthRequest(): AuthorizationRequest {
            val builder: Builder = when {
                "openid" in scope -> OpenIdAuthorizationRequest.Builder(clientId)
                else -> PlainAuthorizationRequest.Builder(clientId)
            }.also { b ->
                extensions?.let { b.setFromExtensions( it ) }
                b.requestParameters = requestParameters
                b.authorities = authorities
                b.scope = scope
                b.resourceIds = resourceIds
                b.redirectUri = redirectUri
                b.responseTypes = responseTypes
                b.state = state
                b.requestTime = requestTime
            }
            @OptIn(InternalForStorage::class)
            (builder as? OpenIdAuthorizationRequest.Builder)?.setFromExtensions(extensions ?: emptyMap())
            return builder.build()
        }

        @OptIn(InternalForStorage::class)
        constructor(plainRequest: PlainAuthorizationRequest): this(
            requestParameters = plainRequest.requestParameters,
            clientId = plainRequest.clientId,
            authorities = plainRequest.authorities,
            isApproved = plainRequest.isApproved,
            scope = plainRequest.scope,
            resourceIds = plainRequest.resourceIds,
            redirectUri = plainRequest.redirectUri,
            responseTypes = plainRequest.responseTypes,
            state = plainRequest.state,
            requestTime = plainRequest.requestTime,
            extensions = plainRequest.authHolderExtensions,
        )

        @OptIn(InternalForStorage::class)
        constructor(oidRequest: OpenIdAuthorizationRequest): this(
            requestParameters = oidRequest.requestParameters,
            clientId = oidRequest.clientId,
            authorities = oidRequest.authorities,
            isApproved = oidRequest.isApproved,
            scope = oidRequest.scope,
            resourceIds = oidRequest.resourceIds,
            redirectUri = oidRequest.redirectUri,
            responseTypes = oidRequest.responseTypes,
            state = oidRequest.state,
            requestTime = oidRequest.requestTime,
            extensions = oidRequest.authHolderExtensions,
        )
    }

    abstract class Builder(var clientId: String) {
        @InternalForStorage
        var requestParameters: Map<String, String> = emptyMap()
        var authorities: Set<GrantedAuthority> = emptySet()
        var approval: Approval? = null
        var scope: Set<String> = emptySet()
        var resourceIds: Set<String>? = null
        var redirectUri: String? = null
        var responseTypes: Set<String>? = null
        var state: String? = null
        var requestTime: ISOInstant? = null
        var codeChallenge: CodeChallenge? = null


        @OptIn(InternalForStorage::class)
        constructor(orig: AuthorizationRequest): this(orig.clientId) {
            requestParameters = orig.requestParameters
            authorities = orig.authorities
            approval = orig.approval
            scope = orig.scope
            resourceIds = orig.resourceIds
            redirectUri = orig.redirectUri
            responseTypes = orig.responseTypes
            state = orig.state
            requestTime = orig.requestTime
            codeChallenge = orig.codeChallenge
        }

        abstract fun build(): AuthorizationRequest

        @InternalForStorage
        abstract fun setFromExtensions(extensions: Map<String, String>)
    }

    companion object : KSerializer<AuthorizationRequest> {
        private val delegate = SerialDelegate.serializer()

        @OptIn(ExperimentalSerializationApi::class)
        override val descriptor: SerialDescriptor =
            SerialDescriptor(delegate.descriptor.serialName.substringBeforeLast(".SerialDelegate"), delegate.descriptor)

        override fun serialize(encoder: Encoder, value: AuthorizationRequest) = when (value) {
            is PlainAuthorizationRequest -> delegate.serialize(encoder, SerialDelegate(value))
            is OpenIdAuthorizationRequest -> delegate.serialize(encoder, SerialDelegate(value))
            else -> throw SerializationException("Unsupported AuthorizationRequest: $value")
        }

        override fun deserialize(decoder: Decoder): AuthorizationRequest {
            return delegate.deserialize(decoder).toAuthRequest()
        }

    }

}

inline fun <T: AuthorizationRequest> T.update(block: AuthorizationRequest.Builder.() -> Unit): T {
    @Suppress("UNCHECKED_CAST")
    return builder().apply(block).build() as T
}

inline fun <T: OpenIdAuthorizationRequest> T.updateOID(block: OpenIdAuthorizationRequest.Builder.() -> Unit): T {
    @Suppress("UNCHECKED_CAST")
    return builder().apply(block).build() as T
}

@RequiresOptIn(message = "This function is internal for use in storage", level = RequiresOptIn.Level.ERROR)
annotation class InternalForStorage
