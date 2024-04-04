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
package org.mitre.openid.connect.model

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.mitre.openid.connect.model.convert.ISODate
import java.util.*
import javax.persistence.*

@Entity
@Table(name = "approved_site")
@NamedQueries(NamedQuery(name = ApprovedSite.QUERY_ALL, query = "select a from ApprovedSite a"), NamedQuery(name = ApprovedSite.QUERY_BY_USER_ID, query = "select a from ApprovedSite a where a.userId = :" + ApprovedSite.PARAM_USER_ID), NamedQuery(name = ApprovedSite.QUERY_BY_CLIENT_ID, query = "select a from ApprovedSite a where a.clientId = :" + ApprovedSite.PARAM_CLIENT_ID), NamedQuery(name = ApprovedSite.QUERY_BY_CLIENT_ID_AND_USER_ID, query = "select a from ApprovedSite a where a.clientId = :" + ApprovedSite.PARAM_CLIENT_ID + " and a.userId = :" + ApprovedSite.PARAM_USER_ID))
class ApprovedSite {

    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    /** which user made the approval */
    @get:Column(name = "user_id")
    @get:Basic
    var userId: String? = null

    /**
     * which OAuth2 client is this tied to
     */
    @get:Column(name = "client_id")
    @get:Basic
    var clientId: String? = null

    /**
     * when was this first approved?
     */
    @get:Column(name = "creation_date")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var creationDate: ISODate? = null

    /**
     * when was this last accessed?
     */
    @get:Column(name = "access_date")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var accessDate: ISODate? = null

    /**
     * if this is a time-limited access, when does it run out?
     */
    @get:Column(name = "timeout_date")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var timeoutDate: ISODate? = null

    /**
     * What scopes have been allowed this should include all information for what data to access
     */
    @get:Column(name = "scope")
    @get:CollectionTable(name = "approved_site_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    var allowedScopes: Set<String>? = null

    /**
     * Has this approval expired?
     */
    @get:Transient
    val isExpired: Boolean
        get() {
            return when (val timeoutDate = timeoutDate) {
                null -> false
                else -> Date().after(timeoutDate)
            }
        }

    @OptIn(ExperimentalSerializationApi::class)
    @Serializable
    class SerialDelegate(
        @EncodeDefault @SerialName("id") val currentId: Long,
        @EncodeDefault @SerialName("accessDate") val accessDate: ISODate? = null,
        @EncodeDefault @SerialName("clientId") val clientId: String,
        @EncodeDefault @SerialName("creationDate") val creationDate: ISODate? = null,
        @EncodeDefault @SerialName("timeoutDate") val timeoutDate: ISODate? = null,
        @EncodeDefault @SerialName("userId") val userId: String? = null,
        @EncodeDefault @SerialName("allowedScopes") val allowedScopes: Set<String>? = null,
        @EncodeDefault @SerialName("whitelistedSiteId") var whitelistedSiteId: Long? = null,
        @EncodeDefault @SerialName("approvedAccessTokens") val approvedAccessTokens: Set<Long> = emptySet(),
    ) {
        constructor(s: ApprovedSite, approvedAccessTokens: Set<Long>): this(
            s.id!!,
            s.accessDate,
            s.clientId!!,
            s.creationDate,
            s.timeoutDate,
            s.userId,
            s.allowedScopes,
            null,
            approvedAccessTokens
        )
    }

    companion object {
        const val QUERY_BY_CLIENT_ID_AND_USER_ID: String = "ApprovedSite.getByClientIdAndUserId"
        const val QUERY_BY_CLIENT_ID: String = "ApprovedSite.getByClientId"
        const val QUERY_BY_USER_ID: String = "ApprovedSite.getByUserId"
        const val QUERY_ALL: String = "ApprovedSite.getAll"

        const val PARAM_CLIENT_ID: String = "clientId"
        const val PARAM_USER_ID: String = "userId"
    }
}
