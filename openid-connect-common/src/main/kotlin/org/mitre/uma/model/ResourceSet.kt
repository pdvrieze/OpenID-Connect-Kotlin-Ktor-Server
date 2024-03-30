/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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
package org.mitre.uma.model

import javax.persistence.*

@Entity
@Table(name = "resource_set")
@NamedQueries(NamedQuery(name = ResourceSet.QUERY_BY_OWNER, query = "select r from ResourceSet r where r.owner = :" + ResourceSet.PARAM_OWNER), NamedQuery(name = ResourceSet.QUERY_BY_OWNER_AND_CLIENT, query = "select r from ResourceSet r where r.owner = :" + ResourceSet.PARAM_OWNER + " and r.clientId = :" + ResourceSet.PARAM_CLIENTID), NamedQuery(name = ResourceSet.QUERY_BY_CLIENT, query = "select r from ResourceSet r where r.clientId = :" + ResourceSet.PARAM_CLIENTID), NamedQuery(name = ResourceSet.QUERY_ALL, query = "select r from ResourceSet r"))
class ResourceSet {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "name")
    @get:Basic
    var name: String? = null

    @get:Column(name = "uri")
    @get:Basic
    var uri: String? = null

    @get:Column(name = "rs_type")
    @get:Basic
    var type: String? = null

    @get:CollectionTable(name = "resource_set_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:Column(name = "scope")
    @get:ElementCollection(fetch = FetchType.EAGER)
    var scopes: Set<String> = HashSet()

    @get:Column(name = "icon_uri")
    @get:Basic
    var iconUri: String? = null

    /** username of the person responsible for the registration (either directly or via OAuth token) */
    @get:Column(name = "owner")
    @get:Basic
    var owner: String? = null

    /** client id of the protected resource that registered this resource set via OAuth token */
    @get:Column(name = "client_id")
    @get:Basic
    var clientId: String? = null

    @get:JoinColumn(name = "resource_set_id")
    @get:OneToMany(cascade = [CascadeType.ALL], fetch = FetchType.EAGER)
    var policies: MutableCollection<Policy>? = HashSet()

    /* (non-Javadoc)
    * @see java.lang.Object#toString()
    */
    override fun toString(): String {
        return "ResourceSet [id=$id, name=$name, uri=$uri, type=$type, scopes=$scopes, iconUri=$iconUri, owner=$owner, clientId=$clientId, policies=$policies]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ResourceSet

        if (id != other.id) return false
        if (name != other.name) return false
        if (uri != other.uri) return false
        if (type != other.type) return false
        if (scopes != other.scopes) return false
        if (iconUri != other.iconUri) return false
        if (owner != other.owner) return false
        if (clientId != other.clientId) return false
        if (policies != other.policies) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id?.hashCode() ?: 0
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (uri?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + (scopes?.hashCode() ?: 0)
        result = 31 * result + (iconUri?.hashCode() ?: 0)
        result = 31 * result + (owner?.hashCode() ?: 0)
        result = 31 * result + (clientId?.hashCode() ?: 0)
        result = 31 * result + (policies?.hashCode() ?: 0)
        return result
    }


    companion object {
        const val QUERY_BY_OWNER: String = "ResourceSet.queryByOwner"
        const val QUERY_BY_OWNER_AND_CLIENT: String = "ResourceSet.queryByOwnerAndClient"
        const val QUERY_BY_CLIENT: String = "ResourceSet.queryByClient"
        const val QUERY_ALL: String = "ResourceSet.queryAll"

        const val PARAM_OWNER: String = "owner"
        const val PARAM_CLIENTID: String = "clientId"
    }
}
