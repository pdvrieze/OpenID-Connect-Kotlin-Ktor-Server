package io.github.pdvrieze.auth.exposed

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.statements.UpdateBuilder
import org.jetbrains.exposed.sql.update
import org.mitre.oauth2.model.SystemScope

abstract class RepositoryBase(protected val database: Database, vararg val tables: Table) {
    init {
        org.jetbrains.exposed.sql.transactions.transaction(database) {
            SchemaUtils.create(*tables)
        }
    }

    protected fun <T> transaction(statement: Transaction.() -> T): T {
        return org.jetbrains.exposed.sql.transactions.transaction(database, statement)
    }


    protected inline fun Table.save(id: Long?, crossinline builder: (UpdateBuilder<Int>) -> Unit): Long = transaction {
        when (id) {
            null -> {
                val newId = SystemScopes.insertAndGetId {
                    builder(it)
                }
                newId.value
            }

            else -> { // update
                SystemScopes.update({ SystemScopes.id eq id}) {
                    builder(it)
                }
                id
            }
        }
    }

    private fun SystemScope.toUpdate(
        builder: UpdateBuilder<Int>
    ) {
        builder[SystemScopes.value] = value!!
        builder[SystemScopes.description] = description
        builder[SystemScopes.icon] = icon
        builder[SystemScopes.defaultScope] = isDefaultScope
        builder[SystemScopes.restricted] = isRestricted
    }


}
