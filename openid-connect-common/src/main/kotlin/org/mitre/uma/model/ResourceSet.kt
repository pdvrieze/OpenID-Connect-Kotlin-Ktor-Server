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

import kotlinx.serialization.Serializable

/**
 * @property owner Username of the person responsible for the registration (either directly or via OAuth token)
 * @property clientId Client id of the protected resource that registered this resource set via OAuth token
 */
@Serializable
class ResourceSet(
    @Transient
    var id: Long? = null,
    var name: String,
    var uri: String? = null,
    var type: String? = null,
    var scopes: Set<String> = emptySet(),
    var iconUri: String? = null,
    var owner: String? = null,
    var clientId: String? = null,
    var policies: Collection<Policy> = emptyList(),
) {

    fun copy(
        id: Long? = this.id,
        name: String = this.name,
        uri: String? = this.uri,
        type: String? = this.type,
        scopes: Set<String> = this.scopes,
        iconUri: String? = this.iconUri,
        owner: String? = this.owner,
        clientId: String? = this.clientId,
        policies: Collection<Policy> = this.policies,
    ) : ResourceSet = ResourceSet(id, name, uri, type, scopes.toHashSet(), iconUri, owner, clientId, policies.toList())

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
        result = 31 * result + name.hashCode()
        result = 31 * result + (uri?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + scopes.hashCode()
        result = 31 * result + (iconUri?.hashCode() ?: 0)
        result = 31 * result + (owner?.hashCode() ?: 0)
        result = 31 * result + (clientId?.hashCode() ?: 0)
        result = 31 * result + policies.hashCode()
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
