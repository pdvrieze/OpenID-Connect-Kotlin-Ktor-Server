package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable

object SystemScopes : LongIdTable("system_scope") {
    val value = varchar("scope", 256).uniqueIndex()
    val description = varchar("description", 4096).nullable()
    val icon = varchar("icon", 256).nullable()
    val restricted = bool("restricted").default(false)
    val defaultScope = bool("default_scope").default(false)
}
