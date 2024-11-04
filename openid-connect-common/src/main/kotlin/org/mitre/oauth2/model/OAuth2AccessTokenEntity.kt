package org.mitre.oauth2.model

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.oauth2.resolver.AuthenticationHolderResolver
import org.mitre.oauth2.resolver.ClientResolver
import org.mitre.oauth2.resolver.OAuth2TokenResolver
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.openid.connect.model.convert.ISOInstant
import org.mitre.uma.model.Permission
import java.time.Instant
import java.util.*

/**
 * Create a new, blank access token
 *
 * @author jricher
 * @property authenticationHolder The authentication in place when this token was created.
 */
//@Table(name = "access_token")
//@NamedQueries(
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_ALL, query = "select a from OAuth2AccessTokenEntity a"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_EXPIRED_BY_DATE, query = "select a from OAuth2AccessTokenEntity a where a.expiration <= :${OAuth2AccessTokenEntity.PARAM_DATE}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_REFRESH_TOKEN, query = "select a from OAuth2AccessTokenEntity a where a.refreshToken = :${OAuth2AccessTokenEntity.PARAM_REFRESH_TOKEN}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_CLIENT, query = "select a from OAuth2AccessTokenEntity a where a.client = :${OAuth2AccessTokenEntity.PARAM_CLIENT}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_TOKEN_VALUE, query = "select a from OAuth2AccessTokenEntity a where a.jwt = :${OAuth2AccessTokenEntity.PARAM_TOKEN_VALUE}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_APPROVED_SITE, query = "select a from OAuth2AccessTokenEntity a where a.approvedSite = :${OAuth2AccessTokenEntity.PARAM_APPROVED_SITE}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_RESOURCE_SET, query = "select a from OAuth2AccessTokenEntity a join a.permissions p where p.resourceSet.id = :${OAuth2AccessTokenEntity.PARAM_RESOURCE_SET_ID}"),
//    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_NAME, query = "select r from OAuth2AccessTokenEntity r where r.authenticationHolder.userAuth.name = :${OAuth2AccessTokenEntity.PARAM_NAME}")
//)
class OAuth2AccessTokenEntity(
    var id: Long? = null,
    override var client: OAuthClientDetails? = null,
    override var authenticationHolder: AuthenticationHolderEntity,
    override var jwt: JWT, // JWT-encoded access token value
    override val expirationInstant: Instant,
    override val tokenType: String = OAuth2AccessToken.BEARER_TYPE,
    override val refreshToken: OAuth2RefreshTokenEntity? = null,
    override val scope: Set<String> = emptySet(),
) : OAuth2AccessToken {

    @Deprecated("Use expirationInstant")
    override val expiration: Date?
        get() = when (expirationInstant) {
            Instant.MIN -> null
            else ->Date.from(expirationInstant)
        }

    var permissions: Set<Permission>? = null

    var approvedSite: ApprovedSite? = null

    private val additionalInformation: MutableMap<String, JsonElement> =
        HashMap() // ephemeral map of items to be added to the OAuth token response

    constructor(
        id: Long? = null,
        expiration: Date,
        jwt: JWT,
        client: OAuthClientDetails? = null,
        authenticationHolder: AuthenticationHolderEntity,
        refreshToken: OAuth2RefreshTokenEntity? = null,
        scope: Set<String>? = null,
        tokenType: String = OAuth2AccessToken.BEARER_TYPE,
    ) : this(
        id = id,
        expirationInstant = expiration.toInstant(),
        jwt = jwt,
        client = client,
        authenticationHolder = authenticationHolder,
        refreshToken = refreshToken,
        scope = scope ?: emptySet(),
        tokenType = tokenType,
    )

    /**
     * Get all additional information to be sent to the serializer as part of the token response.
     * This map is not persisted to the database.
     */
    fun getAdditionalInformation(): MutableMap<String, JsonElement> {
        return additionalInformation
    }

    @Deprecated("Secondary value")
    override val value: String
        get() = jwt.serialize()

    override val isExpired: Boolean
        get() = expirationInstant > Instant.now()

    /**
     * Add the ID Token to the additionalInformation map for a token response.
     */
    fun setIdToken(idToken: JWT?) {
        if (idToken != null) {
            additionalInformation[ID_TOKEN_FIELD_NAME] = Json.parseToJsonElement(idToken.serialize())
        }
    }

    fun serialDelegate(): SerialDelegate = SerialDelegate(this)

    fun copy(
        id: Long? = this.id,
        client: OAuthClientDetails? = this.client,
        authenticationHolder: AuthenticationHolderEntity = this.authenticationHolder,
        jwt: JWT = this.jwt,
        expirationInstant: Instant = this.expirationInstant,
        tokenType: String = this.tokenType,
        refreshToken: OAuth2RefreshTokenEntity? = this.refreshToken,
        scope: Set<String> = this.scope,
    ): OAuth2AccessTokenEntity {
        return OAuth2AccessTokenEntity(
            id = id,
            client = client,
            authenticationHolder = authenticationHolder,
            jwt = jwt,
            expirationInstant = expirationInstant,
            tokenType = tokenType,
            refreshToken = refreshToken,
            scope = scope,
        )
    }

    override fun builder(): Builder {
        return Builder(this)
    }

    class Builder(
        var currentId: Long? = null,
        var expirationInstant: Instant? = null,
        override var jwt: JWT? = null,
        clientId: String? = null,
        authenticationHolderId: Long? = null,
        refreshTokenId: Long? = null,
        var scope: Set<String>? = null,
        var tokenType: String = OAuth2AccessToken.BEARER_TYPE,
        var approvedSite: ApprovedSite? = null,
        var permissions: Set<Permission>? = null,
    ) : OAuth2AccessToken.Builder {

        var refreshTokenId = refreshTokenId
            set(value) {
                field = value
                if (refreshToken?.id != value) refreshToken = null
            }

        private var refreshToken: OAuth2RefreshTokenEntity? = null
            set(value) {
                field = value
                if (refreshTokenId != value?.id) refreshTokenId = value?.id
            }

        override var expiration: Date?
            get() = expirationInstant?.let { Date.from(it) }
            set(value) {
                expirationInstant = value?.toInstant()
            }

        var clientId = clientId
            private set(value) {
                field = value
                if (client?.clientId != value) {
                    client = null
                }
            }

        private var client: OAuthClientDetails? = null

        var authenticationHolderId = authenticationHolderId
            set(value) {
                if (authenticationHolder?.id != value) {
                    authenticationHolder = null
                }
                field = value
            }

        private var authenticationHolder: AuthenticationHolderEntity? = null

        private val additionalInformation: MutableMap<String, JsonElement> =
            HashMap() // ephemeral map of items to be added to the OAuth token response

        constructor(
            currentId: Long? = null,
            expirationInstant: Instant? = null,
            jwt: JWT? = null,
            client: OAuthClientDetails,
            authenticationHolderId: Long? = null,
            refreshTokenId: Long? = null,
            scope: Set<String>? = null,
            tokenType: String = OAuth2AccessToken.BEARER_TYPE,
            approvedSite: ApprovedSite? = null,
            permissions: Set<Permission>? = null,
        ) : this(
            currentId = currentId,
            expirationInstant = expirationInstant,
            jwt = jwt,
            clientId = client.clientId,
            authenticationHolderId = authenticationHolderId,
            refreshTokenId = refreshTokenId,
            scope = scope,
            tokenType = tokenType,
            approvedSite = approvedSite,
            permissions = permissions
        ) {
            this.client = client
        }

        constructor(token: OAuth2AccessTokenEntity) : this(
            currentId = token.id,
            expirationInstant = token.expirationInstant,
            jwt = token.jwt,
            clientId = token.client?.clientId,
            authenticationHolderId = token.authenticationHolder.id,
            refreshTokenId = token.refreshToken?.id,
            scope = token.scope,
            tokenType = token.tokenType,
            approvedSite = token.approvedSite,
            permissions = token.permissions
        )

        fun setClient(client: OAuthClientDetails) {
            this.client = client
            clientId = client.clientId
        }

        fun setAuthenticationHolder(authenticationHolder: AuthenticationHolderEntity?) {
            this.authenticationHolder = authenticationHolder
            this.authenticationHolderId = authenticationHolder?.id
        }

        fun setRefreshToken(t: OAuth2RefreshTokenEntity?, dummy: Boolean = false) {
            this.refreshToken = t
        }

        override fun setIdToken(idToken: JWT?) {
            if (idToken != null) {
                additionalInformation[ID_TOKEN_FIELD_NAME] = Json.parseToJsonElement(idToken.serialize())
            }
        }

        fun build(
            clientService: ClientResolver,
            authenticationHolderResolver: AuthenticationHolderResolver,
            tokenResolver: OAuth2TokenResolver,
        ): OAuth2AccessTokenEntity {
            val client: ClientDetailsEntity? = (client ?: clientId?.let {
                clientService.loadClientByClientId(it)
            })?.let { c -> ClientDetailsEntity.from(c) }

            return build(client, authenticationHolderResolver, tokenResolver)
        }

        fun build(
            client: ClientDetailsEntity?,
            authenticationHolderResolver: AuthenticationHolderResolver,
            tokenRepository: OAuth2TokenResolver,
        ): OAuth2AccessTokenEntity {
            val authenticationHolder =
                authenticationHolder ?: authenticationHolderId?.let { authenticationHolderResolver.getById(it) }
            val refreshToken = refreshToken ?: refreshTokenId?.let { tokenRepository.getRefreshTokenById(it) }
            return OAuth2AccessTokenEntity(
                id = currentId,
                expirationInstant = (expiration?.toInstant() ?: Instant.MIN),
                jwt = jwt ?: PlainJWT(JWTClaimsSet.Builder().build()),
                client = client,
                authenticationHolder = authenticationHolder ?: AuthenticationHolderEntity(requestTime = Instant.now()),
                refreshToken = refreshToken,
                scope = scope ?: emptySet(),
                tokenType = tokenType,
            ).also { t ->
                approvedSite?.let { t.approvedSite = it }
                t.additionalInformation.putAll(additionalInformation)
                t.permissions = permissions
            }
        }
    }

    @Serializable
    class SerialDelegate internal constructor(
        @SerialName("id")
        val currentId: Long,
        @SerialName("expiration")
        @EncodeDefault val expiration: ISOInstant? = null,
        @SerialName("value")
        @EncodeDefault val value: @Serializable(JWTStringConverter::class) JWT? = null,
        @SerialName("clientId")
        val clientId: String,
        @SerialName("authenticationHolderId")
        val authenticationHolderId: Long,
        @SerialName("refreshTokenId")
        @EncodeDefault val refreshTokenId: Long? = null,
        @SerialName("scope")
        @EncodeDefault val scope: Set<String>? = null,
        @SerialName("type")
        @EncodeDefault val tokenType: String = OAuth2AccessToken.BEARER_TYPE,
    ) {

        constructor(s: OAuth2AccessTokenEntity) : this(
            currentId = s.id!!,
            expiration = s.expirationInstant,
            value = s.jwt,
            clientId = s.client!!.clientId,
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
