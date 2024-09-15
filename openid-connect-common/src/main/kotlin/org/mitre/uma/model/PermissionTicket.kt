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

/**
 *
 * An UMA permission, used in the protection API.
 *
 * @author jricher
 */
//@NamedQueries(NamedQuery(name = PermissionTicket.QUERY_TICKET, query = "select p from PermissionTicket p where p.ticket = :" + PermissionTicket.PARAM_TICKET), NamedQuery(name = PermissionTicket.QUERY_ALL, query = "select p from PermissionTicket p"), NamedQuery(name = PermissionTicket.QUERY_BY_RESOURCE_SET, query = "select p from PermissionTicket p where p.permission.resourceSet.id = :" + PermissionTicket.PARAM_RESOURCE_SET_ID))
class PermissionTicket(
    val id: Long? = null,
    val permission: Permission,
    val ticket: String? = null,
    val expiration: Date? = null,
    claimsSupplied: Collection<Claim>? = null
) {
    val claimsSupplied: Set<Claim>? = claimsSupplied?.toHashSet()

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
