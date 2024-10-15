package io.github.pdvrieze.auth.exposed

import io.github.pdvrieze.auth.repository.exposed.SystemScopes
import org.jetbrains.exposed.dao.id.IdTable
import org.jetbrains.exposed.sql.Column
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.Transaction
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.insertAndGetId
import org.jetbrains.exposed.sql.statements.UpdateBuilder
import org.jetbrains.exposed.sql.transactions.transaction
import org.jetbrains.exposed.sql.update
import org.mitre.oauth2.model.SystemScope
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

abstract class RepositoryBase(protected val database: Database, vararg val tables: Table) {
    init {
        transaction(database) {
            SchemaUtils.create(*tables)
        }
    }

    @OptIn(ExperimentalContracts::class)
    protected fun <T> transaction(statement: Transaction.() -> T): T {
        contract {
            callsInPlace(statement, InvocationKind.EXACTLY_ONCE)
        }
        return transaction(database, statement)
    }


    protected inline fun <T: IdTable<K>, K: Comparable<K>> T.save(id: K?, crossinline builder: T.(UpdateBuilder<Int>) -> Unit): K = transaction {
        val t = this@save
        when (id) {
            null -> {
                val newId = t.insertAndGetId {
                    builder(it)
                }
                newId.value
            }

            else -> { // update
                t.update({ t.id eq id}) {
                    builder(it)
                }
                id
            }
        }
    }

    protected fun Transaction.saveStrings(data: Collection<String>?, table: Table, idColumn: Column<Long>, idValue: Long, dataColumn: Column<String>) {
        if(data.isNullOrEmpty()) return
        table.batchInsert(data) { value ->
            this[idColumn] = idValue
            this[dataColumn] = value
        }
    }

}
