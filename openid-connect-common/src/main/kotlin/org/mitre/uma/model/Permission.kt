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
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.ElementCollection
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.ManyToOne
import javax.persistence.Table

/**
 * @author  jricher
 */
@Entity
@Table(name = "permission")
@Serializable
class Permission {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:JoinColumn(name = "resource_set_id")
    @get:ManyToOne(fetch = FetchType.EAGER)
    lateinit var resourceSet: ResourceSet

    @get:CollectionTable(name = "permission_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:Column(name = "scope")
    @get:ElementCollection(fetch = FetchType.EAGER)
    var scopes: Set<String> = emptySet()

    @Deprecated("For JPA")
    constructor()

    constructor(id: Long? = null, resourceSet: ResourceSet? = null, scopes: Set<String>) {
        this.id = id
        resourceSet?.let { this.resourceSet = it }
        this.scopes = scopes.toSet()
    }

    fun copy(id: Long? = this.id, resourceSet: ResourceSet? = this.resourceSet, scopes:Set<String> = this.scopes): Permission {
        return Permission(id, resourceSet, scopes)
    }
}
