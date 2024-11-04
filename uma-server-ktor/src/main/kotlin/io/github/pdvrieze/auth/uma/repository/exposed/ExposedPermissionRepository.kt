package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import io.github.pdvrieze.auth.repository.exposed.Permissions
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.JoinType
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.uma.repository.ResourceSetRepository
import java.util.*

class ExposedPermissionRepository(database: Database, private val resourceSets: ResourceSetRepository) :
    RepositoryBase(database, Permissions, PermissionScopes, PermissionTickets), PermissionRepository {

    override fun save(p: PermissionTicket): PermissionTicket {
        val oldId = p.id

        val newId = transaction {
            val permission = saveRawPermission(p.permission)

            PermissionTickets.save(oldId) { b ->
                b[ticket] = p.ticket!!
                b[permissionId] = permission.id!!
                b[expiration] = p.expiration?.toInstant()
            }
        }
        return p.copy(id = newId)
    }

    override fun getByTicket(ticket: String): PermissionTicket? {
        return transaction {
            PermissionTickets.selectAll()
                .where(PermissionTickets.ticket eq ticket)
                .map { it.toPermissionTicket() }
                .singleOrNull()
        }
    }

    override val all: Collection<PermissionTicket>
        get() {
            return transaction {
                PermissionTickets.selectAll().map { it.toPermissionTicket() }
            }
        }

    override fun saveRawPermission(p: Permission): Permission {
        val newId = transaction {
            val oldId = p.id
            val newId = Permissions.save(oldId) { b ->
                b[resourceSetId] = p.resourceSet.id
            }
            if (oldId != null) {
                PermissionScopes.deleteWhere { ownerId eq oldId }
            }
            PermissionScopes.batchInsert(p.scopes) { scope ->
                set(PermissionScopes.ownerId, newId)
                set(PermissionScopes.scope, scope)
            }
            newId
        }
        return p.copy(id = newId)
    }

    override fun getById(permissionId: Long): Permission? {
        return Permissions.selectAll().where { Permissions.id eq permissionId }.map { it.toPermission() }.singleOrNull()
    }

    override fun getPermissionTicketsForResourceSet(rs: ResourceSet): Collection<PermissionTicket> {
        return PermissionTickets.join(Permissions, JoinType.INNER, PermissionTickets.permissionId, Permissions.id)
            .select(PermissionTickets.columns)
            .where { Permissions.resourceSetId eq rs.id }
            .map { it.toPermissionTicket() }
    }

    override fun remove(ticket: PermissionTicket) {
        PermissionTickets.deleteWhere { PermissionTickets.id eq ticket.id }
    }

    fun ResultRow.toPermission(): Permission {
        val permId = get(Permissions.id).value
        val resourceSetId = get(Permissions.resourceSetId)
        val resourceSet = checkNotNull(resourceSetId?.let { resourceSets.getById(it) }) {
            "Missing resource set $resourceSetId for permission $permId"
        }

        val scopes = PermissionScopes.select(PermissionScopes.scope)
            .where { PermissionScopes.ownerId eq permId }
            .mapTo(mutableSetOf()) { it[PermissionScopes.scope]}

        return Permission(
            id = permId,
            resourceSet = resourceSet,
            scopes = scopes,
        )
    }

    fun ResultRow.toPermissionTicket(): PermissionTicket {
        val ticketId = get(PermissionTickets.id).value
        val permId = get(PermissionTickets.permissionId)
        val perm = Permissions.selectAll().where { Permissions.id eq permId }.single().toPermission()

        val scopes = PermissionScopes.select(PermissionScopes.scope)
            .where { PermissionScopes.ownerId eq permId }
            .mapTo(mutableSetOf()) { it[PermissionScopes.scope]}

        return PermissionTicket(
            id = ticketId,
            permission = perm,
            expiration = get(PermissionTickets.expiration)?.let { Date.from(it) },
        )
    }

}
