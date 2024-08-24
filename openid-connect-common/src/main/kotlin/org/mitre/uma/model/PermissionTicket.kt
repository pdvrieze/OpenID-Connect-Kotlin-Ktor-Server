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

import java.util.*
import javax.persistence.*

/**
 *
 * An UMA permission, used in the protection API.
 *
 * @author jricher
 */
@Entity
@Table(name = "permission_ticket")
@NamedQueries(NamedQuery(name = PermissionTicket.QUERY_TICKET, query = "select p from PermissionTicket p where p.ticket = :" + PermissionTicket.PARAM_TICKET), NamedQuery(name = PermissionTicket.QUERY_ALL, query = "select p from PermissionTicket p"), NamedQuery(name = PermissionTicket.QUERY_BY_RESOURCE_SET, query = "select p from PermissionTicket p where p.permission.resourceSet.id = :" + PermissionTicket.PARAM_RESOURCE_SET_ID))
class PermissionTicket {
    @get:Column(name = "id")
    @get:GeneratedValue(strategy = GenerationType.IDENTITY)
    @get:Id
    var id: Long? = null

    @get:JoinColumn(name = "permission_id")
    @get:OneToOne(fetch = FetchType.EAGER, cascade = [CascadeType.ALL])
    lateinit var permission: Permission

    @get:Column(name = "ticket")
    @get:Basic
    var ticket: String? = null

    @get:Column(name = "expiration")
    @get:Temporal(TemporalType.TIMESTAMP)
    @get:Basic
    var expiration: Date? = null

    @get:JoinTable(name = "claim_to_permission_ticket", joinColumns = [JoinColumn(name = "permission_ticket_id")], inverseJoinColumns = [JoinColumn(name = "claim_id")])
    @get:OneToMany(cascade = [CascadeType.ALL], fetch = FetchType.EAGER)
    var claimsSupplied: Collection<Claim>? = null

    @Deprecated("For JPA")
    constructor()

    constructor(id: Long? = null, permission: Permission, ticket: String? = null, expiration: Date? = null, claimsSupplied: Collection<Claim>? = null) {
        this.id = id
        this.permission = permission
        this.ticket = ticket
        this.expiration = expiration
        this.claimsSupplied = claimsSupplied?.toHashSet()
    }

    fun copy(
        id: Long? = this.id,
        permission: Permission = this.permission,
        ticket: String? = this.ticket,
        expiration: Date? = this.expiration,
        claimsSupplied: Collection<Claim>? = this.claimsSupplied,
    ): PermissionTicket {
        return PermissionTicket(id, permission, ticket, expiration, claimsSupplied)
    }

    companion object {
        const val QUERY_TICKET: String = "PermissionTicket.queryByTicket"
        const val QUERY_ALL: String = "PermissionTicket.queryAll"
        const val QUERY_BY_RESOURCE_SET: String = "PermissionTicket.queryByResourceSet"

        const val PARAM_TICKET: String = "ticket"
        const val PARAM_RESOURCE_SET_ID: String = "rsid"
    }
}
