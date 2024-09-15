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
import org.mitre.openid.connect.model.ApprovedSite.Companion.PARAM_CLIENT_ID
import org.mitre.openid.connect.model.ApprovedSite.Companion.PARAM_USER_ID
import org.mitre.openid.connect.model.ApprovedSite.Companion.QUERY_ALL
import org.mitre.openid.connect.model.ApprovedSite.Companion.QUERY_BY_CLIENT_ID
import org.mitre.openid.connect.model.ApprovedSite.Companion.QUERY_BY_CLIENT_ID_AND_USER_ID
import org.mitre.openid.connect.model.ApprovedSite.Companion.QUERY_BY_USER_ID
import org.mitre.openid.connect.model.convert.ISODate
import java.util.*

//    NamedQuery(name = QUERY_ALL, query = "select a from ApprovedSite a"),
//    NamedQuery(name = QUERY_BY_USER_ID, query = "select a from ApprovedSite a where a.userId = :$PARAM_USER_ID"),
//    NamedQuery(name = QUERY_BY_CLIENT_ID, query = "select a from ApprovedSite a where a.clientId = :$PARAM_CLIENT_ID"),
//    NamedQuery(name = QUERY_BY_CLIENT_ID_AND_USER_ID, query = "select a from ApprovedSite a where a.clientId = :$PARAM_CLIENT_ID and a.userId = :$PARAM_USER_ID"))
/**
 * @property clientId which OAuth2 client is this tied to
 * @property creationDate when was this first approved?
 * @property accessDate when was this last accessed?
 * @property timeoutDate if this is a time-limited access, when does it run out?
 * @property allowedScopes What scopes have been allowed this should include all information for what data to access
 */
class ApprovedSite(
    var id: Long? = null,
    var userId: String?,
    var clientId: String?,
    var creationDate: ISODate? = null,
    var accessDate: ISODate? = null,
    var timeoutDate: ISODate? = null,
    var allowedScopes: Set<String> = emptySet(),
) {

    /**
     * Has this approval expired?
     */
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
        @EncodeDefault @SerialName("id")
        val currentId: Long,
        @EncodeDefault @SerialName("accessDate")
        val accessDate: ISODate? = null,
        @EncodeDefault @SerialName("clientId")
        val clientId: String,
        @EncodeDefault @SerialName("creationDate")
        val creationDate: ISODate? = null,
        @EncodeDefault @SerialName("timeoutDate")
        val timeoutDate: ISODate? = null,
        @EncodeDefault @SerialName("userId")
        val userId: String? = null,
        @EncodeDefault @SerialName("allowedScopes")
        val allowedScopes: Set<String>? = null,
        @EncodeDefault @SerialName("whitelistedSiteId")
        var whitelistedSiteId: Long? = null,
        @EncodeDefault @SerialName("approvedAccessTokens")
        val approvedAccessTokens: Set<Long> = emptySet(),
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
