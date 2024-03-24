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
/**
 *
 */
package org.mitre.oauth2.model

import com.nimbusds.jwt.JWT
import org.codehaus.jackson.map.annotate.JsonDeserialize
import org.codehaus.jackson.map.annotate.JsonSerialize
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.uma.model.Permission
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson1Deserializer
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson1Serializer
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Deserializer
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Serializer
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import java.util.*
import javax.persistence.*

/**
 * Create a new, blank access token
 *
 * @author jricher
 */
@Entity
@Table(name = "access_token")
@NamedQueries(
    NamedQuery(name = OAuth2AccessTokenEntity.QUERY_ALL, query = "select a from OAuth2AccessTokenEntity a"), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_EXPIRED_BY_DATE, query = "select a from OAuth2AccessTokenEntity a where a.expiration <= :" + OAuth2AccessTokenEntity.PARAM_DATE), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_REFRESH_TOKEN, query = "select a from OAuth2AccessTokenEntity a where a.refreshToken = :" + OAuth2AccessTokenEntity.PARAM_REFERSH_TOKEN), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_CLIENT, query = "select a from OAuth2AccessTokenEntity a where a.client = :" + OAuth2AccessTokenEntity.PARAM_CLIENT), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_TOKEN_VALUE, query = "select a from OAuth2AccessTokenEntity a where a.jwt = :" + OAuth2AccessTokenEntity.PARAM_TOKEN_VALUE), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_APPROVED_SITE, query = "select a from OAuth2AccessTokenEntity a where a.approvedSite = :" + OAuth2AccessTokenEntity.PARAM_APPROVED_SITE), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_RESOURCE_SET, query = "select a from OAuth2AccessTokenEntity a join a.permissions p where p.resourceSet.id = :" + OAuth2AccessTokenEntity.PARAM_RESOURCE_SET_ID), NamedQuery(name = OAuth2AccessTokenEntity.QUERY_BY_NAME, query = "select r from OAuth2AccessTokenEntity r where r.authenticationHolder.userAuth.name = :" + OAuth2AccessTokenEntity.PARAM_NAME)
)
@JsonSerialize(using = OAuth2AccessTokenJackson1Serializer::class)
@JsonDeserialize(using = OAuth2AccessTokenJackson1Deserializer::class)
@com.fasterxml.jackson.databind.annotation.JsonSerialize(using = OAuth2AccessTokenJackson2Serializer::class)
@com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer::class)
class OAuth2AccessTokenEntity : OAuth2AccessToken {
	@get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

	@get:JoinColumn(name = "client_id")
    @get:ManyToOne
    var client: ClientDetailsEntity? = null

    /**
     * The authentication in place when this token was created.
     */
	@get:JoinColumn(name = "auth_holder_id")
    @get:ManyToOne
    var authenticationHolder: AuthenticationHolderEntity? = null // the authentication that made this access

    @get:Convert(converter = JWTStringConverter::class)
    @get:Column(name = "token_value")
    @get:Basic
    var jwt: JWT? = null // JWT-encoded access token value

    private var expiration: Date? = null

    private var tokenType = OAuth2AccessToken.BEARER_TYPE

    private var refreshToken: OAuth2RefreshTokenEntity? = null

    private var scope: Set<String>? = null

	@get:JoinTable(name = "access_token_permissions", joinColumns = [JoinColumn(name = "access_token_id")], inverseJoinColumns = [JoinColumn(name = "permission_id")])
    @get:OneToMany(fetch = FetchType.EAGER, cascade = [CascadeType.ALL])
    var permissions: Set<Permission>? = null

	@get:JoinColumn(name = "approved_site_id")
    @get:ManyToOne
    var approvedSite: ApprovedSite? = null

    private val additionalInformation: MutableMap<String, Any> =
        HashMap() // ephemeral map of items to be added to the OAuth token response

    /**
     * Get all additional information to be sent to the serializer as part of the token response.
     * This map is not persisted to the database.
     */
    @Transient
    override fun getAdditionalInformation(): Map<String, Any> {
        return additionalInformation
    }

    /**
     * Get the string-encoded value of this access token.
     */
    @Transient
    override fun getValue(): String {
        return jwt!!.serialize()
    }

    @Basic
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "expiration")
    override fun getExpiration(): Date? {
        return expiration
    }

    fun setExpiration(expiration: Date?) {
        this.expiration = expiration
    }

    @Basic
    @Column(name = "token_type")
    override fun getTokenType(): String {
        return tokenType
    }

    fun setTokenType(tokenType: String) {
        this.tokenType = tokenType
    }

    @ManyToOne
    @JoinColumn(name = "refresh_token_id")
    override fun getRefreshToken(): OAuth2RefreshTokenEntity? {
        return refreshToken
    }

    fun setRefreshToken(refreshToken: OAuth2RefreshTokenEntity?) {
        this.refreshToken = refreshToken
    }

    fun setRefreshToken(refreshToken: OAuth2RefreshToken?) {
        require(refreshToken is OAuth2RefreshTokenEntity) { "Not a storable refresh token entity!" }
        // force a pass through to the entity version
        setRefreshToken(refreshToken as OAuth2RefreshTokenEntity?)
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(joinColumns = [JoinColumn(name = "owner_id")], name = "token_scope")
    override fun getScope(): Set<String>? {
        return scope
    }

    fun setScope(scope: Set<String>?) {
        this.scope = scope
    }

    @Transient
    override fun isExpired(): Boolean {
        return getExpiration()?.let { System.currentTimeMillis() > it.time } ?: false
    }

    @Transient
    override fun getExpiresIn(): Int {
        return when (val e = getExpiration()) {
            null -> -1 // no expiration time

            else -> {
                val millisRemaining = e.time - System.currentTimeMillis()
                when {
                    millisRemaining <= 0 -> 0 // has an expiration time and expired
                    else -> (millisRemaining / 1000).toInt() // has an expiration time and not expired
                }
            }
        }
    }

    /**
     * Add the ID Token to the additionalInformation map for a token response.
     */
    @Transient
    fun setIdToken(idToken: JWT?) {
        if (idToken != null) {
            additionalInformation[ID_TOKEN_FIELD_NAME] = idToken.serialize()
        }
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
        const val PARAM_REFERSH_TOKEN: String = "refreshToken"
        const val PARAM_DATE: String = "date"
        const val PARAM_RESOURCE_SET_ID: String = "rsid"
        const val PARAM_APPROVED_SITE: String = "approvedSite"
        const val PARAM_NAME: String = "name"

        const val ID_TOKEN_FIELD_NAME: String = "id_token"
    }
}
