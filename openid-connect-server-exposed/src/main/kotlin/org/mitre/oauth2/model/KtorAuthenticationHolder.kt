package org.mitre.oauth2.model

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.convert.AuthenticationSerializer
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.OpenIdAuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest

class KtorAuthenticationHolder private constructor(
    override val id: Long?,
    override val userAuthentication: SavedUserAuthentication?,
    override val authorizationRequest: AuthorizationRequest,
) : AuthenticationHolder {

    constructor(
        authentication: AuthenticatedAuthorizationRequest,
        id: Long? = null,
    ): this(
        id,
        authentication.userAuthentication?.let(SavedUserAuthentication.Companion::from),
        authentication.authorizationRequest,
    )

    constructor(
        authentication: Authentication?,
        authorizationRequest: AuthorizationRequest,
        id: Long? = null
    ): this(
        id = id,
        userAuthentication = authentication?.let(SavedUserAuthentication.Companion::from),
        authorizationRequest = authorizationRequest,
    )

    override fun copy(id: Long?): KtorAuthenticationHolder {
        return copy(id, this.userAuthentication)
    }

    fun copy(
        id: Long? = this.id,
        userAuth: SavedUserAuthentication? = this.userAuthentication,
        authorizationRequest: AuthorizationRequest = this.authorizationRequest,
    ): KtorAuthenticationHolder {
        return KtorAuthenticationHolder(
            id = id,
            userAuthentication = userAuth,
            authorizationRequest = authorizationRequest,
        )
    }

//    @KXS_Serializable
//    private class AuthenticationEntry(
//        val clientAuthorization: AuthorizationRequest? = null,
//        val userAuthentication: JsonElement? = null,
//        val savedUserAuthentication: SavedUserAuthentication? = null,
//    )

    interface SerialDelegate {
        fun toAuthenticationHolder(): KtorAuthenticationHolder
    }

    @Serializable
    class SerialDelegate10(
        @SerialName("id")
        val currentId: Long? = null,
        @SerialName("ownerId")
        val ownerId: JsonElement? = null,
        @SerialName("authentication")
        val _authentication: AuthenticatedAuthorizationRequest/*? = null*/,
    ) : SerialDelegate {
        constructor(e: AuthenticationHolder) : this(
            currentId = e.id,
            _authentication = e
        )

        override fun toAuthenticationHolder(): KtorAuthenticationHolder {
            return KtorAuthenticationHolder(
                _authentication,
                id = currentId,
            )
        }
    }

    @Serializable
    class Authentication12(
        @SerialName("authorizationRequest")
        val authorizationRequest: AuthorizationRequest12,
        @SerialName("savedUserAuthentication")
        val userAuth: @Serializable(AuthenticationSerializer::class) Authentication? = null,
    )

    @Serializable
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    class AuthorizationRequest12(
        @SerialName("requestParameters")
        @EncodeDefault val requestParameters: Map<String, String> = emptyMap(),
        @SerialName("clientId")
        @EncodeDefault val clientId: String? = null,
        @SerialName("scope")
        @EncodeDefault val scope: Set<String>? = null,
        @SerialName("resourceIds")
        @EncodeDefault val resourceIds: Set<String>? = null,
        @SerialName("authorities")
        @EncodeDefault val authorities: Collection<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority> = emptyList(),
        @SerialName("approved")
        @EncodeDefault val isApproved: Boolean = false,
        @SerialName("redirectUri")
        @EncodeDefault val redirectUri: String? = null,
        @SerialName("responseTypes")
        @EncodeDefault val responseTypes: Set<String> = emptySet(),
        @SerialName("extensions")
        @EncodeDefault val extensions: Map<String, String> = emptyMap(),
    )

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @Serializable
    class SerialDelegate12(
        @SerialName("id")
        val currentId: Long,
        @SerialName("authentication")
        val authentication: Authentication12? = null,
        @SerialName("authorizationRequest")
        val authorizationRequest: AuthorizationRequest? = null,
        @SerialName("requestParameters")
        val requestParameters: Map<String, String>? = null,
        @SerialName("clientId")
        val clientId: String? = null,
        @SerialName("scope")
        val scope: Set<String>? = null,
        @SerialName("resourceIds")
        val resourceIds: Set<String>? = null,
        @SerialName("authorities")
        val authorities: Set<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority>? = null,
        @SerialName("approved")
        val isApproved: Boolean? = null,
        @SerialName("redirectUri")
        val redirectUri: String? = null,
        @SerialName("responseTypes")
        val responseTypes: Set<String>? = null,
        @SerialName("extensions")
        val extensions: Map<String, String>? = null,
        @SerialName("savedUserAuthentication")
        val userAuth: @Serializable(AuthenticationSerializer::class) Authentication? = null,
    ) : SerialDelegate {
        constructor(e: AuthenticationHolder) : this(
            currentId = e.id!!,
            requestParameters = e.authorizationRequest.requestParameters ?: emptyMap(),
            clientId = requireNotNull(e.authorizationRequest.clientId) { "ClientId must be set" },
            scope = e.authorizationRequest.scope,
            resourceIds = e.authorizationRequest.resourceIds,
            authorities = e.authorizationRequest.authorities.toHashSet(),
            isApproved = e.authorizationRequest.isApproved,
            redirectUri = e.authorizationRequest.redirectUri,
            responseTypes = e.authorizationRequest.responseTypes ?: emptySet(),
            extensions = e.authorizationRequest.authHolderExtensions.asSequence()?.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }?.associate { it } ?: emptyMap(),
            userAuth = e.userAuthentication,
        )

        override fun toAuthenticationHolder(): KtorAuthenticationHolder {
            val userAuth = userAuth?.let { it as? SavedUserAuthentication ?: SavedUserAuthentication(it) }

            val r = authentication?.authorizationRequest

            val authRequest = when (r) {
                null -> {
                    when {
                        scope?.contains("openid") == true -> OpenIdAuthorizationRequest.Builder(clientId!!)
                        else -> PlainAuthorizationRequest.Builder(clientId!!)
                    }.also { b ->
                        b.setFromExtensions(extensions ?:emptyMap())
                        b.authorities = authorities?.toSet() ?: emptySet()
                        b.resourceIds = resourceIds
                        b.redirectUri = redirectUri
                        b.responseTypes = responseTypes

                        b.clientId = clientId
                        b.scope = scope?.toHashSet() ?: emptySet()
                        b.requestParameters = requestParameters ?: emptyMap()
                    }
                }
                else -> when {
                    r.scope?.contains("openid") == true -> OpenIdAuthorizationRequest.Builder(r.clientId!!)
                    else -> PlainAuthorizationRequest.Builder(r.clientId!!)
                }.also { b ->
                    b.setFromExtensions(r.extensions)
                    b.authorities = r.authorities.toSet()
                    b.resourceIds = r.resourceIds
                    b.redirectUri = r.redirectUri
                    b.responseTypes = r.responseTypes

                    b.clientId = r.clientId
                    b.scope = r.scope?.toHashSet() ?: emptySet()
                    b.requestParameters = r.requestParameters
                }
            }.build()

            return KtorAuthenticationHolder(
                authentication = userAuth,
                authorizationRequest = authRequest,
                id = currentId
            )
        }
    }

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    abstract class SerializerBase<T: SerialDelegate>(version: String, private val delegate: kotlinx.serialization.KSerializer<T>):
        kotlinx.serialization.KSerializer<KtorAuthenticationHolder> {

        override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor =
            kotlinx.serialization.descriptors.SerialDescriptor("org.mitre.oauth2.model.AuthenticationHolderEntity.$version", delegate.descriptor)

        override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): KtorAuthenticationHolder {
            return delegate.deserialize(decoder).toAuthenticationHolder()
        }

        abstract fun KtorAuthenticationHolder.toDelegate(): T

        override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: KtorAuthenticationHolder) {
            delegate.serialize(encoder, value.toDelegate())
        }

    }

    companion object {
        operator fun invoke(orig: AuthenticatedAuthorizationRequest): KtorAuthenticationHolder = when(orig){
            is KtorAuthenticationHolder -> KtorAuthenticationHolder(orig, orig.id)
            else -> KtorAuthenticationHolder(orig)
        }
    }

    object Serializer10 : SerializerBase<SerialDelegate10>("1.0", SerialDelegate10.serializer()) {
        override fun KtorAuthenticationHolder.toDelegate(): SerialDelegate10 = SerialDelegate10(this)
    }

    object Serializer12 : SerializerBase<SerialDelegate12>("1.2", SerialDelegate12.serializer()) {
        override fun KtorAuthenticationHolder.toDelegate(): SerialDelegate12 = SerialDelegate12(this)
    }
}
