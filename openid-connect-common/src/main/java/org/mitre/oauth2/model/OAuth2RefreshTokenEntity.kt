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
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.convert.JWTStringConverter
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import java.util.*
import javax.persistence.*
import kotlin.math.exp

/**
 * @author jricher
 */
@Entity
@Table(name = "refresh_token")
@NamedQueries(NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_ALL, query = "select r from OAuth2RefreshTokenEntity r"), NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_EXPIRED_BY_DATE, query = "select r from OAuth2RefreshTokenEntity r where r.expiration <= :" + OAuth2RefreshTokenEntity.PARAM_DATE), NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_CLIENT, query = "select r from OAuth2RefreshTokenEntity r where r.client = :" + OAuth2RefreshTokenEntity.PARAM_CLIENT), NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_TOKEN_VALUE, query = "select r from OAuth2RefreshTokenEntity r where r.jwt = :" + OAuth2RefreshTokenEntity.PARAM_TOKEN_VALUE), NamedQuery(name = OAuth2RefreshTokenEntity.QUERY_BY_NAME, query = "select r from OAuth2RefreshTokenEntity r where r.authenticationHolder.userAuth.name = :" + OAuth2RefreshTokenEntity.PARAM_NAME))
class OAuth2RefreshTokenEntity : OAuth2RefreshToken {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    /**
     * The authentication in place when the original access token was created
     */
    @get:JoinColumn(name = "auth_holder_id")
    @get:ManyToOne
    var authenticationHolder: AuthenticationHolderEntity? = null

    @get:JoinColumn(name = "client_id")
    @get:ManyToOne(fetch = FetchType.EAGER)
    var client: ClientDetailsEntity? = null

    /**
     * Get the JWT object directly
     */
    //JWT-encoded representation of this access token entity
    @get:Convert(converter = JWTStringConverter::class)
    @get:Column(name = "token_value")
    @get:Basic
    var jwt: JWT? = null

    // our refresh tokens might expire
    @get:Column(name = "expiration")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var expiration: Date? = null

    /**
     * Get the JWT-encoded value of this token
     */
    @Transient
    override fun getValue(): String {
        return jwt!!.serialize()
    }

    /**
     * Has this token expired?
     * true if it has a timeout set and the timeout has passed
     */
    @get:Transient
    val isExpired: Boolean
        get() = expiration?.let { System.currentTimeMillis() > it.time } ?: false

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
