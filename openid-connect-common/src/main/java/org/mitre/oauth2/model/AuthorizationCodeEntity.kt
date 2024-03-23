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

import org.mitre.oauth2.model.AuthorizationCodeEntity
import java.util.*
import javax.persistence.*

/**
 * Entity class for authorization codes
 *
 * @author aanganes
 */
@Entity
@Table(name = "authorization_code")
@NamedQueries(NamedQuery(name = AuthorizationCodeEntity.QUERY_BY_VALUE, query = "select a from AuthorizationCodeEntity a where a.code = :code"), NamedQuery(name = AuthorizationCodeEntity.QUERY_EXPIRATION_BY_DATE, query = "select a from AuthorizationCodeEntity a where a.expiration <= :" + AuthorizationCodeEntity.PARAM_DATE))
class AuthorizationCodeEntity {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "code")
    @get:Basic
    var code: String? = null

    /**
     * The authentication in place when this token was created.
     */
    @get:JoinColumn(name = "auth_holder_id")
    @get:ManyToOne
    var authenticationHolder: AuthenticationHolderEntity? = null

    @get:Column(name = "expiration")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var expiration: Date? = null

    constructor()

    /**
     * Create a new AuthorizationCodeEntity with the given code and AuthorizationRequestHolder.
     *
     * @param code            the authorization code
     * @param authenticationHolder    the AuthoriztionRequestHolder associated with the original code request
     * @param expiration The expiration date
     */
    constructor(
        code: String? = null,
        authenticationHolder: AuthenticationHolderEntity? = null,
        expiration: Date? = null,
    ) {
        this.code = code
        this.authenticationHolder = authenticationHolder
        this.expiration = expiration
    }

    companion object {
        const val QUERY_BY_VALUE: String = "AuthorizationCodeEntity.getByValue"
        const val QUERY_EXPIRATION_BY_DATE: String = "AuthorizationCodeEntity.expirationByDate"

        const val PARAM_DATE: String = "date"
    }
}
