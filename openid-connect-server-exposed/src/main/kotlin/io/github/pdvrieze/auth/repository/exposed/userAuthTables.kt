package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table

object SavedUserAuths : LongIdTable("saved_user_auth") {
    val name = varchar("name", 1024).nullable()
    val authenticated = bool("authenticated").default(false)
    val sourceClass = varchar("source_class", 2048).nullable()
}

object SavedUserAuthAuthorities : Table("saved_user_auth_authority") {
    val ownerId = long("owner_id").references(SavedUserAuths.id)
    val authority = varchar("authority", 256).nullable()
}
