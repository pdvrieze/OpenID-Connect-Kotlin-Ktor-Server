/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.oauth2.model

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.convert.AuthenticationSerializer
import org.mitre.oauth2.model.convert.KXS_OAuth2Authentication
import org.mitre.oauth2.model.convert.OAuth2Request
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import javax.persistence.Transient
import kotlinx.serialization.Serializable as KXS_Serializable
import java.io.Serializable as IoSerializable

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
    var id: Long? = null,
    var userAuth: SavedUserAuthentication? = null,
    var authorities: Collection<GrantedAuthority>? = null,
    var resourceIds: Set<String>? = null,
    var isApproved: Boolean = false,
    var redirectUri: String? = null,
    var responseTypes: Set<String>? = null,
    var extensions: Map<String, IoSerializable>? = null,
    var clientId: String? = null,
    var scope: Set<String>? = null,
    var requestParameters: Map<String, String>? = null,
) {
    @get:Transient
    var authentication: OAuth2Authentication
        get() =// TODO: memoize this
            OAuth2Authentication(createOAuth2Request(), userAuth)
        set(authentication) {
            // pull apart the request and save its bits

            val o2Request = authentication.oAuth2Request
            authorities = o2Request.authorities.toHashSet()
            clientId = o2Request.clientId
            extensions = o2Request.extensionStrings?.toMap()
            redirectUri = o2Request.redirectUri
            requestParameters = o2Request.requestParameters.toMap()
            resourceIds = o2Request.resourceIds?.toHashSet()
            responseTypes = o2Request.responseTypes?.toHashSet()
            scope = if (o2Request.scope == null) null else HashSet(o2Request.scope)
            isApproved = o2Request.isApproved

            if (authentication.userAuthentication != null) {
                this.userAuth = SavedUserAuthentication(authentication.userAuthentication)
            } else {
                this.userAuth = null
            }
        }

    private fun createOAuth2Request(): OAuth2Request {
        return OAuth2Request(
            requestParameters = requestParameters ?: emptyMap(),
            clientId = clientId!!,
            authorities = authorities?.toSet() ?: emptySet(),
            isApproved = isApproved,
            scope = scope ?: emptySet(),
            resourceIds = resourceIds,
            redirectUri = redirectUri,
            responseTypes = responseTypes,
            extensionStrings = extensions?.let { m -> m.mapValues { it.toString() } } ?: emptyMap<String, String>(),
        )
    }

    fun copy(
        id: Long? = this.id,
        userAuth: SavedUserAuthentication? = this.userAuth,
        authorities: Collection<GrantedAuthority>? = this.authorities,
        resourceIds: Set<String>? = this.resourceIds,
        isApproved: Boolean = this.isApproved,
        redirectUri: String? = this.redirectUri,
        responseTypes: Set<String>? = this.responseTypes,
        extensions: Map<String, IoSerializable>? = this.extensions,
        clientId: String? = this.clientId,
        scope: Set<String>? = this.scope,
        requestParameters: Map<String, String>? = this.requestParameters,
    ): AuthenticationHolderEntity {
        return AuthenticationHolderEntity(
            id = id,
            userAuth = userAuth,
            authorities = authorities,
            resourceIds = resourceIds,
            isApproved = isApproved,
            redirectUri = redirectUri,
            responseTypes = responseTypes,
            extensions = extensions,
            clientId = clientId,
            scope = scope,
            requestParameters = requestParameters,
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

    @KXS_Serializable
    public class SerialDelegate10(
        @SerialName("id") val currentId: Long? = null,
        @SerialName("ownerId") val ownerId: JsonElement? = null,
        @SerialName("authentication") val _authentication: KXS_OAuth2Authentication? = null,
    ) : SerialDelegate {
        constructor(e: AuthenticationHolderEntity) : this(
            currentId = e.id,
            _authentication = e.authentication
        )

        override fun toAuthenticationHolder(): AuthenticationHolderEntity {
            return AuthenticationHolderEntity(
                id = currentId,
            ).also {
                if (_authentication != null) it.authentication = _authentication
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    @KXS_Serializable
    public class SerialDelegate12(
        @SerialName("id") val currentId: Long,
        @SerialName("requestParameters") @EncodeDefault val requestParameters: Map<String, String> = emptyMap(),
        @SerialName("clientId") @EncodeDefault val clientId: String? = null,
        @SerialName("scope") @EncodeDefault val scope: Set<String>? = null,
        @SerialName("resourceIds") @EncodeDefault val resourceIds: Set<String>? = null,
        @SerialName("authorities") @EncodeDefault val authorities: Collection<@Serializable(SimpleGrantedAuthorityStringConverter::class) GrantedAuthority> = emptyList(),
        @SerialName("approved") @EncodeDefault val isApproved: Boolean = false,
        @SerialName("redirectUri") @EncodeDefault val redirectUri: String? = null,
        @SerialName("responseTypes") @EncodeDefault val responseTypes: Set<String> = emptySet(),
        @SerialName("extensions") @EncodeDefault val extensions: Map<String, String> = emptyMap(),
        @SerialName("authorizationRequest") val authorizationRequest: OAuth2Request? = null,
        @SerialName("savedUserAuthentication") val userAuth: @Serializable(AuthenticationSerializer::class) Authentication? = null,
    ) : SerialDelegate {
        constructor(e: AuthenticationHolderEntity) : this(
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
                requestParameters = requestParameters

            )
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    abstract class SerializerBase<T: SerialDelegate>(version: String, private val delegate: KSerializer<T>): KSerializer<AuthenticationHolderEntity> {

        override val descriptor: SerialDescriptor =
            SerialDescriptor("org.mitre.oauth2.model.AuthenticationHolderEntity.$version", delegate.descriptor)

        override fun deserialize(decoder: Decoder): AuthenticationHolderEntity {
            return delegate.deserialize(decoder).toAuthenticationHolder()
        }

        abstract fun AuthenticationHolderEntity.toDelegate(): T

        override fun serialize(encoder: Encoder, value: AuthenticationHolderEntity) {
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
