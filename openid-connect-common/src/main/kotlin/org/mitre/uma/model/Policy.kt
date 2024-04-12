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
import javax.persistence.Basic
import javax.persistence.CascadeType
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.ElementCollection
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.JoinTable
import javax.persistence.OneToMany
import javax.persistence.Table

/**
 * A set of claims required to fulfill a given permission.
 *
 * @author jricher
 */
@Entity
@Table(name = "policy")
@Serializable
class Policy {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:Column(name = "name")
    @get:Basic
    var name: String? = null

    @get:JoinTable(name = "claim_to_policy", joinColumns = [JoinColumn(name = "policy_id")], inverseJoinColumns = [JoinColumn(name = "claim_id")])
    @get:OneToMany(cascade = [CascadeType.ALL], fetch = FetchType.EAGER)
    var claimsRequired: Collection<Claim>? = null

    @get:CollectionTable(name = "policy_scope", joinColumns = [JoinColumn(name = "owner_id")])
    @get:Column(name = "scope")
    @get:ElementCollection(fetch = FetchType.EAGER)
    var scopes: Set<String> = emptySet()

    override fun toString(): String {
        return "Policy [id=$id, name=$name, claimsRequired=$claimsRequired, scopes=$scopes]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Policy

        if (id != other.id) return false
        if (name != other.name) return false
        if (claimsRequired != other.claimsRequired) return false
        if (scopes != other.scopes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id?.hashCode() ?: 0
        result = 31 * result + (name?.hashCode() ?: 0)
        result = 31 * result + (claimsRequired?.hashCode() ?: 0)
        result = 31 * result + scopes.hashCode()
        return result
    }

}
