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

import com.nimbusds.jwt.JWT
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.convert.ISODate
import org.mitre.uma.model.Permission
import java.time.Instant
import java.util.*
import javax.persistence.*
import javax.persistence.Transient as JPATransient

/**
 * Create a new, blank access token
 *
 * @author jricher
 */
@Entity
@Table(name = "access_token")
@NamedQueries(
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_ALL, query = "select a from OAuth2AccessTokenEntity a"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_EXPIRED_BY_DATE, query = "select a from OAuth2AccessTokenEntity a where a.expiration <= :${OAuth2AccessTokenEntity.PARAM_DATE}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_REFRESH_TOKEN, query = "select a from OAuth2AccessTokenEntity a where a.refreshToken = :${OAuth2AccessTokenEntity.PARAM_REFRESH_TOKEN}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_CLIENT, query = "select a from OAuth2AccessTokenEntity a where a.client = :${OAuth2AccessTokenEntity.PARAM_CLIENT}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_TOKEN_VALUE, query = "select a from OAuth2AccessTokenEntity a where a.jwt = :${OAuth2AccessTokenEntity.PARAM_TOKEN_VALUE}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_APPROVED_SITE, query = "select a from OAuth2AccessTokenEntity a where a.approvedSite = :${OAuth2AccessTokenEntity.PARAM_APPROVED_SITE}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_RESOURCE_SET, query = "select a from OAuth2AccessTokenEntity a join a.permissions p where p.resourceSet.id = :${OAuth2AccessTokenEntity.PARAM_RESOURCE_SET_ID}"),
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_NAME, query = "select r from OAuth2AccessTokenEntity r where r.authenticationHolder.userAuth.name = :${OAuth2AccessTokenEntity.PARAM_NAME}")
)
class OAuth2AccessTokenEntity : OAuth2AccessToken {
	@get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

	@get:JoinColumn(name = "client_id")
    @ManyToOne
    var client: OAuthClientDetails? = null

    /**
     * The authentication in place when this token was created.
     */
	@get:JoinColumn(name = "auth_holder_id")
    @ManyToOne
    lateinit var authenticationHolder: AuthenticationHolderEntity // the authentication that made this access

    @get:Convert(converter = JWTStringConverter::class)
    @get:Column(name = "token_value")
    @get:Basic
    lateinit var jwt: JWT // JWT-encoded access token value

    override lateinit var expirationInstant: Instant
        private set

    override var expiration: Date
        get() = Date.from(expirationInstant)
        private set(value) {
            expirationInstant = value.toInstant()
        }

    override var tokenType = OAuth2AccessToken.BEARER_TYPE
        private set

    @ManyToOne
    @JoinColumn(name = "refresh_token_id")
    override var refreshToken: OAuth2RefreshTokenEntity? = null
        internal set

    override lateinit var scope: Set<String>
        private set



	@get:JoinTable(name = "access_token_permissions", joinColumns = [JoinColumn(name = "access_token_id")], inverseJoinColumns = [JoinColumn(name = "permission_id")])
    @get:OneToMany(fetch = FetchType.EAGER, cascade = [CascadeType.ALL])
    var permissions: Set<Permission>? = null

	@get:JoinColumn(name = "approved_site_id")
    @ManyToOne
    var approvedSite: ApprovedSite? = null

    private val additionalInformation: MutableMap<String, JsonElement> =
        HashMap() // ephemeral map of items to be added to the OAuth token response

    @Deprecated("Only for JPA uses")
    constructor()

    constructor(
        id: Long?,
        expiration: Date,
        jwt: JWT,
        client: ClientDetailsEntity?,
        authenticationHolder: AuthenticationHolderEntity,
        refreshToken: OAuth2RefreshTokenEntity?,
        scope: Set<String>?,
        tokenType: String,
    ) {
        this.id = id
        this.expirationInstant = expiration.toInstant()
        this.jwt = jwt
        this.client = client
        this.authenticationHolder = authenticationHolder
        this.refreshToken = refreshToken
        this.scope = scope ?: emptySet()
        this.tokenType = tokenType
    }

    constructor(
        id: Long?,
        expiration: Instant,
        jwt: JWT,
        client: ClientDetailsEntity?,
        authenticationHolder: AuthenticationHolderEntity,
        refreshToken: OAuth2RefreshTokenEntity,
        scope: Set<String>?,
        tokenType: String,
    ) {
        this.id = id
        this.expirationInstant = expiration
        this.jwt = jwt
        this.client = client
        this.authenticationHolder = authenticationHolder
        this.refreshToken = refreshToken
        this.scope = scope ?: emptySet()
        this.tokenType = tokenType
    }

    /**
     * Get all additional information to be sent to the serializer as part of the token response.
     * This map is not persisted to the database.
     */
    fun getAdditionalInformation(): MutableMap<String, JsonElement> {
        return additionalInformation
    }

    override val value: String
        get() = jwt.serialize()

    fun setRefreshToken(refreshToken: OAuth2RefreshToken?) {
        require(refreshToken is OAuth2RefreshTokenEntity) { "Not a storable refresh token entity!" }
        // force a pass through to the entity version
        this.refreshToken = refreshToken as OAuth2RefreshTokenEntity
    }


    override val isExpired: Boolean
        get() = expirationInstant > Instant.now()

    /**
     * Add the ID Token to the additionalInformation map for a token response.
     */
    @JPATransient
    fun setIdToken(idToken: JWT?) {
        if (idToken != null) {
            additionalInformation[ID_TOKEN_FIELD_NAME] = Json.parseToJsonElement(idToken.serialize())
        }
    }

    @JPATransient
    fun serialDelegate(): SerialDelegate = SerialDelegate(this)

    @Serializable
    class SerialDelegate internal constructor(
        @SerialName("id") val currentId: Long,
        @SerialName("expiration") @EncodeDefault val expiration: ISODate? = null,
        @SerialName("value") @EncodeDefault val value: @Serializable(JWTStringConverter::class) JWT? = null,
        @SerialName("clientId") val clientId: String,
        @SerialName("authenticationHolderId")  val authenticationHolderId: Long,
        @SerialName("refreshTokenId") @EncodeDefault val refreshTokenId: Long? = null,
        @SerialName("scope") @EncodeDefault val scope: Set<String>? = null,
        @SerialName("type") @EncodeDefault val tokenType: String = OAuth2AccessToken.BEARER_TYPE
    ) {

        constructor(s: OAuth2AccessTokenEntity): this(
            currentId = s.id!!,
            expiration = s.expiration,
            value = s.jwt,
            clientId = s.client!!.getClientId()!!,
            authenticationHolderId = s.authenticationHolder.id!!,
            refreshTokenId = s.refreshToken?.id,
            scope = s.scope,
            tokenType = s.tokenType
        )
    }

    companion object {
        const val QUERY_BY_APPROVED_SITE: String = "OAuth2AccessTokenEntity.getByApprovedSite"
        const val QUERY_BY_TOKEN_VALUE: String = "OAuth2AccessTokenEntity.getByTokenValue"
        const val QUERY_BY_CLIENT: String = "OAuth2AccessTokenEntity.getByClient"
        const val QUERY_BY_REFRESH_TOKEN: String = "OAuth2AccessTokenEntity.getByRefreshToken"
        const val QUERY_EXPIRED_BY_DATE: String = "OAuth2AccessTokenEntity.getAllExpiredByDate"
        const val QUERY_ALL: String = "OAuth2AccessTokenEntity.getAll"
        const val QUERY_BY_RESOURCE_SET: String = "OAuth2AccessTokenEntity.getByResourceSet"
        const val QUERY_BY_NAME: String = "OAuth2AccessTokenEntity.getByName"

        const val PARAM_TOKEN_VALUE: String = "tokenValue"
        const val PARAM_CLIENT: String = "client"
        const val PARAM_REFRESH_TOKEN: String = "refreshToken"
        const val PARAM_DATE: String = "date"
        const val PARAM_RESOURCE_SET_ID: String = "rsid"
        const val PARAM_APPROVED_SITE: String = "approvedSite"
        const val PARAM_NAME: String = "name"

        const val ID_TOKEN_FIELD_NAME: String = "id_token"

    }
}
