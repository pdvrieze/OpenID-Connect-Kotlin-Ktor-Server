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
import kotlinx.serialization.Serializable
import javax.persistence.Basic
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.ElementCollection
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.NamedQueries
import javax.persistence.NamedQuery
import javax.persistence.Table

/**
 * Indicator that login to a site should be automatically granted
 * without user interaction.
 * @author jricher, aanganes
 */
@OptIn(ExperimentalSerializationApi::class)
@Entity
@Table(name = "whitelisted_site")
@NamedQueries(NamedQuery(name = WhitelistedSite.QUERY_ALL, query = "select w from WhitelistedSite w"), NamedQuery(name = WhitelistedSite.QUERY_BY_CLIENT_ID, query = "select w from WhitelistedSite w where w.clientId = :" + WhitelistedSite.PARAM_CLIENT_ID), NamedQuery(name = WhitelistedSite.QUERY_BY_CREATOR, query = "select w from WhitelistedSite w where w.creatorUserId = :" + WhitelistedSite.PARAM_USER_ID))
@Serializable
class WhitelistedSite(
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    @EncodeDefault
    var id: Long? = null,

    /** Reference to the admin user who created this entry */
    @get:Column(name = "creator_user_id")
    @get:Basic
    @EncodeDefault
    var creatorUserId: String? = null,

    /**
     * which OAuth2 client is this tied to
     */
    @get:Column(name = "client_id")
    @get:Basic
    @EncodeDefault
    var clientId: String? = null,

    /**
     * What scopes be allowed by default. this should include all information for what data to access
     */
    @get:Column(name = "scope")
    @get:CollectionTable(name = "whitelisted_site_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:ElementCollection(fetch = FetchType.EAGER)
    @EncodeDefault
    var allowedScopes: Set<String>? = null,
) {

    @Serializable
    class SerialDelegate(

    )

    companion object {
        const val QUERY_BY_CREATOR: String = "WhitelistedSite.getByCreatoruserId"
        const val QUERY_BY_CLIENT_ID: String = "WhitelistedSite.getByClientId"
        const val QUERY_ALL: String = "WhitelistedSite.getAll"

        const val PARAM_USER_ID: String = "userId"
        const val PARAM_CLIENT_ID: String = "clientId"
    }
}
