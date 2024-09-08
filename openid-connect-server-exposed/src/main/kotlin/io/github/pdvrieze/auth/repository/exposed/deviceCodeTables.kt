package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp

object DeviceCodes : LongIdTable("device_code") {
    val deviceCode = varchar("device_code", 1024).nullable()
    val userCode = varchar("user_code", 1024).nullable()
    val expiration = timestamp("expiration").nullable().default(null)
    val clientId = varchar("client_id", 256).references(ClientDetails.clientId).nullable()
    val approved = bool("approved").nullable()
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id).nullable()
}

object DeviceCodeScopes : Table("device_code_scope") {
    val ownerId = long("owner_id") // TODO add foreign key
    val scope = varchar("scope", 256)
}

object DeviceCodeRequestParameters : Table("device_code_request_parameter") {
    val ownerId = long("owner_id").nullable() // TODO add foreign key
    val param = varchar("param", 2048)
    val value = varchar("val", 2048)
}
