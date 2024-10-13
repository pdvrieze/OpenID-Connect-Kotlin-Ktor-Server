package io.github.pdvrieze.auth.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.UpdateBuilder
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.oauth2.model.SystemScope
import org.mitre.oauth2.repository.SystemScopeRepository

class ExposedSystemScopeRepository(database: Database):
    RepositoryBase(database, SystemScopes), SystemScopeRepository {

    override val all: Set<SystemScope>
        get() = transaction {
            SystemScopes.selectAll().orderBy(SystemScopes.id).mapTo(HashSet()) {
                it.toSystemScope()
            }
        }

    private fun ResultRow.toSystemScope() = SystemScope(
        id = get(SystemScopes.id).value,
        value = get(SystemScopes.value),
        description = get(SystemScopes.description),
        icon = get(SystemScopes.icon),
        isDefaultScope = get(SystemScopes.defaultScope),
        isRestricted = get(SystemScopes.restricted),
    )

    override fun getById(id: Long): SystemScope? = transaction {
        SystemScopes.selectAll().where { SystemScopes.id eq id }.singleOrNull()?.toSystemScope()
    }

    override fun getByValue(value: String): SystemScope? = transaction {
        SystemScopes.selectAll().where { SystemScopes.value eq value }.singleOrNull()?.toSystemScope()
    }

    override fun remove(scope: SystemScope) {
        val id = scope.id ?: return
        return transaction(database) {
            SystemScopes.deleteWhere { SystemScopes.id eq id }
        }
    }

    override fun save(scope: SystemScope): SystemScope = transaction {
        val newId = SystemScopes.save(scope.id) { scope.toUpdate(it) }

        scope.apply { id = newId }
    }

    private fun SystemScope.toUpdate(
        builder: UpdateBuilder<Int>
    ) {
        builder[SystemScopes.value] = value!!
        description?.let { builder[SystemScopes.description] = it }
        icon?.let { builder[SystemScopes.icon] = it }
        builder[SystemScopes.defaultScope] = isDefaultScope
        builder[SystemScopes.restricted] = isRestricted
    }
}
