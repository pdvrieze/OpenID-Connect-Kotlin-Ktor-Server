package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.javatime.timestamp

object AuthorizationCodes : LongIdTable("authorization_code") {
    val code = varchar("code", 256).nullable()
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id).nullable()
    val expiration = timestamp("expiration").nullable().default(null)
}
