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
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.mitre.openid.connect.model.convert.ISODate
import java.time.Instant
import java.util.*

/**
 * @author jricher
 */
//@Table(name = "refresh_token")
//@NamedQueries(
//    NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_ALL, query = "select r from OAuth2RefreshTokenEntity r"),
//    NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_EXPIRED_BY_DATE, query = "select r from OAuth2RefreshTokenEntity r where r.expiration <= :${OAuth2RefreshTokenEntity.PARAM_DATE}"),
//    NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_CLIENT, query = "select r from OAuth2RefreshTokenEntity r where r.client = :${OAuth2RefreshTokenEntity.PARAM_CLIENT}"),
//    NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_TOKEN_VALUE, query = "select r from OAuth2RefreshTokenEntity r where r.jwt = :${OAuth2RefreshTokenEntity.PARAM_TOKEN_VALUE}"),
//    NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_NAME, query = "select r from OAuth2RefreshTokenEntity r where r.authenticationHolder.userAuth.name = :${OAuth2RefreshTokenEntity.PARAM_NAME}"))
class OAuth2RefreshTokenEntity : OAuth2RefreshToken {
    var id: Long? = null

    /**
     * The authentication in place when the original access token was created
     */
    lateinit var authenticationHolder: AuthenticationHolder

    var client: OAuthClientDetails? = null

    /**
     * Get the JWT object directly
     */
    //JWT-encoded representation of this access token entity
    lateinit var jwt: JWT

    // our refresh tokens might expire
    var expiration: ISODate?
        get() = Date.from(expirationInstant)
        set(value) { expirationInstant = value?.toInstant() ?: Instant.MIN }

    override var expirationInstant: Instant = Instant.MIN

    @Deprecated("Only present for JPA")
    constructor()

    constructor(
        id: Long? = null,
        authenticationHolder: AuthenticationHolder,
        client: ClientDetailsEntity? = null,
        jwt: JWT = PlainJWT(JWTClaimsSet.Builder().build()),
        expiration: ISODate?,
    ) {
        this.id = id
        this.authenticationHolder = authenticationHolder
        this.client = client
        this.jwt = jwt
        this.expiration = expiration
    }

    constructor(
        id: Long? = null,
        authenticationHolder: AuthenticationHolder,
        client: ClientDetailsEntity? = null,
        jwt: JWT = PlainJWT(JWTClaimsSet.Builder().build()),
        expirationInstant: Instant? = null,
    ) {
        this.id = id
        this.authenticationHolder = authenticationHolder
        this.client = client
        this.jwt = jwt
        this.expirationInstant = expirationInstant ?: Instant.MIN
    }

    /**
     * Get the JWT-encoded value of this token
     */
    override val value: String
        get() = jwt.serialize()

    /**
     * Has this token expired?
     * true if it has a timeout set and the timeout has passed
     */
    val isExpired: Boolean
        get() = expiration?.let { System.currentTimeMillis() > it.time } ?: false

    fun serialDelegate(): SerialDelegate = SerialDelegate(this)

    @Serializable
    class SerialDelegate(
        @SerialName("id")
        val currentId: Long,
        @SerialName("expiration")
        val expiration: ISODate? = null,
        @SerialName("value")
        val value: @Serializable(JWTStringConverter::class) JWT? = null,
        @SerialName("clientId")
        val clientId: String,
        @SerialName("authenticationHolderId")
        val authenticationHolderId: Long,
    ) {
        constructor(s: OAuth2RefreshTokenEntity): this(
            currentId = s.id!!,
            expiration = s.expiration,
            value = s.jwt,
            clientId = s.client!!.clientId,
            authenticationHolderId = s.authenticationHolder.id!!
        )
    }

    companion object {
        const val QUERY_BY_TOKEN_VALUE: String = "OAuth2RefreshTokenEntity.getByTokenValue"
        const val QUERY_BY_CLIENT: String = "OAuth2RefreshTokenEntity.getByClient"
        const val QUERY_EXPIRED_BY_DATE: String = "OAuth2RefreshTokenEntity.getAllExpiredByDate"
        const val QUERY_ALL: String = "OAuth2RefreshTokenEntity.getAll"
        const val QUERY_BY_NAME: String = "OAuth2RefreshTokenEntity.getByName"

        const val PARAM_TOKEN_VALUE: String = "tokenValue"
        const val PARAM_CLIENT: String = "client"
        const val PARAM_DATE: String = "date"
        const val PARAM_NAME: String = "name"
    }
}
