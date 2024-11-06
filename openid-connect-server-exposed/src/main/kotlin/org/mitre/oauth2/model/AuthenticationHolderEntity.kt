package org.mitre.oauth2.model

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.convert.AuthenticationSerializer
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.mitre.oauth2.model.request.AuthorizationRequest
import org.mitre.oauth2.model.request.PlainAuthorizationRequest
import org.mitre.openid.connect.model.convert.ISOInstant
import java.time.Instant

/*
@Entity
@Table(name = "authentication_holder")
@NamedQueries(
    NamedQuery(name = AuthenticationHolderEntity.QUERY_ALL, query = "select a from AuthenticationHolderEntity a"),
    NamedQuery(name = AuthenticationHolderEntity.QUERY_GET_UNUSED, query = "select a from AuthenticationHolderEntity a where " +
                "a.id not in (select t.authenticationHolder.id from OAuth2AccessTokenEntity t) and " +
                "a.id not in (select r.authenticationHolder.id from OAuth2RefreshTokenEntity r) and " +
                "a.id not in (select c.authenticationHolder.id from AuthorizationCodeEntity c)"
    )
)
*/
class AuthenticationHolderEntity(
    override var id: Long? = null,
    override var userAuth: SavedUserAuthentication? = null,
    override var authorities: Collection<GrantedAuthority>? = null,
    override var resourceIds: Set<String>? = null,
    override var isApproved: Boolean = false,
    override var redirectUri: String? = null,
    override var responseTypes: Set<String>? = null,
    override var extensions: Map<String, String>? = null,
    override var clientId: String? = null,
    override var scope: Set<String>? = null,
    override var requestParameters: Map<String, String>? = null,
    override val requestTime: ISOInstant?,
) : AuthenticationHolder {

    constructor(
        authentication: AuthenticatedAuthorizationRequest,
        id: Long? = null,
    ): this(
        authentication.userAuthentication,
        authentication.authorizationRequest,
        id,
    )

    constructor(
        authentication: Authentication?,
        o2Request: AuthorizationRequest,
        id: Long? = null
    ): this(
        id = id,
        userAuth = authentication?.let(SavedUserAuthentication.Companion::from),
        authorities = o2Request.authorities.toHashSet(),
        resourceIds = o2Request.resourceIds?.toHashSet(),
        isApproved = o2Request.isApproved,
        redirectUri = o2Request.redirectUri,
        responseTypes = o2Request.responseTypes?.toHashSet(),
        extensions = o2Request.authHolderExtensions,
        clientId = o2Request.clientId,
        scope = o2Request.scope.toHashSet(),
        requestParameters = o2Request.requestParameters.toMap(),
        requestTime = o2Request.requestTime,
    )

    override val authenticatedAuthorizationRequest: AuthenticatedAuthorizationRequest
        get() = AuthenticatedAuthorizationRequest(createAuthorizationRequest(), userAuth)

    private fun createAuthorizationRequest(): AuthorizationRequest {
        return PlainAuthorizationRequest.Builder(clientId!!).also { b ->
            b.setFromExtensions(extensions?.let { m -> m.mapValues { (_, v) -> v } } ?: emptyMap())

            b.requestParameters = requestParameters ?: emptyMap()
            b.clientId = clientId!!
            b.authorities = authorities?.toSet() ?: emptySet()
            if (isApproved && b.approval == null) {
                b.approval =
                    AuthorizationRequest.Approval(Instant.EPOCH) // mark long ago //setFromExtensions should handle this
            }

            b.scope = scope ?: emptySet()
            b.resourceIds = resourceIds
            b.redirectUri = redirectUri
            b.responseTypes = responseTypes
            b.requestTime = requestTime
//            extensionStrings = extensions?.let { m -> m.mapValues { (_, v) -> v } },
        }.build()
    }

    override fun copy(id: Long?): AuthenticationHolderEntity {
        return copy(id, this.userAuth)
    }

    fun copy(
        id: Long? = this.id,
        userAuth: SavedUserAuthentication? = this.userAuth,
        authorities: Collection<GrantedAuthority>? = this.authorities,
        resourceIds: Set<String>? = this.resourceIds,
        isApproved: Boolean = this.isApproved,
        redirectUri: String? = this.redirectUri,
        responseTypes: Set<String>? = this.responseTypes,
        extensions: Map<String, String>? = this.extensions,
        clientId: String? = this.clientId,
        scope: Set<String>? = this.scope,
        requestParameters: Map<String, String>? = this.requestParameters,
        requestTime: Instant? = this.requestTime,
    ): AuthenticationHolderEntity {
        return AuthenticationHolderEntity(
            id = id,
            userAuth = userAuth,
            authorities = authorities?.toList(),
            resourceIds = resourceIds?.toHashSet(),
            isApproved = isApproved,
            redirectUri = redirectUri,
            responseTypes = responseTypes?.toSet(),
            extensions = extensions,
            clientId = clientId,
            scope = scope?.toHashSet(),
            requestParameters = requestParameters?.toMap(HashMap()),
            requestTime = requestTime,
        )
    }

//    @KXS_Serializable
//    private class AuthenticationEntry(
//        val clientAuthorization: AuthorizationRequest? = null,
//        val userAuthentication: JsonElement? = null,
//        val savedUserAuthentication: SavedUserAuthentication? = null,
//    )

    interface SerialDelegate {
        fun toAuthenticationHolder(): AuthenticationHolderEntity
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
            _authentication = e.authenticatedAuthorizationRequest
        )

        override fun toAuthenticationHolder(): AuthenticationHolderEntity {
            return AuthenticationHolderEntity(
                _authentication,
                id = currentId,
            )
        }
    }

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @Serializable
    class SerialDelegate12(
        @SerialName("id")
        val currentId: Long,
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
        @SerialName("authorizationRequest")
        val authorizationRequest: AuthorizationRequest? = null,
        @SerialName("savedUserAuthentication")
        val userAuth: @Serializable(AuthenticationSerializer::class) Authentication? = null,
    ) : SerialDelegate {
        constructor(e: AuthenticationHolder) : this(
            currentId = e.id!!,
            requestParameters = e.requestParameters ?: emptyMap(),
            clientId = e.clientId,
            scope = e.scope,
            resourceIds = e.resourceIds,
            authorities = e.authorities ?: emptyList(),
            isApproved = e.isApproved,
            redirectUri = e.redirectUri,
            responseTypes = e.responseTypes ?: emptySet(),
            extensions = e.extensions?.asSequence()?.mapNotNull { (k, v) -> (v as? String)?.let { k to it } }?.associate { it } ?: emptyMap(),
            userAuth = e.userAuth,
        )

        override fun toAuthenticationHolder(): AuthenticationHolderEntity {
            return AuthenticationHolderEntity(
                id = currentId,
                userAuth = userAuth?.let { it as? SavedUserAuthentication ?: SavedUserAuthentication(it) },
                authorities = authorities,
                resourceIds = resourceIds,
                isApproved = isApproved,
                redirectUri = redirectUri,
                responseTypes = responseTypes,
                extensions = extensions,
                clientId = clientId,
                scope = scope,
                requestParameters = requestParameters,
                requestTime = authorizationRequest?.requestTime ?: Instant.MIN,
            )
        }
    }

    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    abstract class SerializerBase<T: SerialDelegate>(version: String, private val delegate: kotlinx.serialization.KSerializer<T>):
        kotlinx.serialization.KSerializer<AuthenticationHolderEntity> {

        override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor =
            kotlinx.serialization.descriptors.SerialDescriptor("org.mitre.oauth2.model.AuthenticationHolderEntity.$version", delegate.descriptor)

        override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): AuthenticationHolderEntity {
            return delegate.deserialize(decoder).toAuthenticationHolder()
        }

        abstract fun AuthenticationHolderEntity.toDelegate(): T

        override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: AuthenticationHolderEntity) {
            delegate.serialize(encoder, value.toDelegate())
        }

    }

    companion object {
        const val QUERY_GET_UNUSED: String = "AuthenticationHolderEntity.getUnusedAuthenticationHolders"
        const val QUERY_ALL: String = "AuthenticationHolderEntity.getAll"
    }

    object Serializer10 : SerializerBase<SerialDelegate10>("1.0", SerialDelegate10.serializer()) {
        override fun AuthenticationHolderEntity.toDelegate(): SerialDelegate10 = SerialDelegate10(this)
    }

    object Serializer12 : SerializerBase<SerialDelegate12>("1.2", SerialDelegate12.serializer()) {
        override fun AuthenticationHolderEntity.toDelegate(): SerialDelegate12 = SerialDelegate12(this)
    }
}
