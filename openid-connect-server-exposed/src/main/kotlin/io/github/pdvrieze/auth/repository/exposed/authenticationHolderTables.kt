package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table


object AuthenticationHolders : LongIdTable("authentication_holder") {
    val userAuthId = long("user_auth_id").references(SavedUserAuths.id).nullable() // TODO add foreign key
    val approved = bool("approved").nullable()
    val redirectUri = varchar("redirect_uri", 2048).nullable()
    val clientId = varchar("client_id", 256).nullable()
}

object AuthenticationHolderAuthorities : Table("authentication_holder_authority") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id) // TODO add foreign key
    val authority = varchar("authority", 256)
}

object AuthenticationHolderResourceIds : Table("authentication_holder_resource_id") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id)
    val resourceId = varchar("resource_id", 2048)
}

object AuthenticationHolderResponseTypes : Table("authentication_holder_response_type") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id)
    val responseType = varchar("response_type", 2048)
}

object AuthenticationHolderExtensions : Table("authentication_holder_extension") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id)
    val extension = varchar("extension", 2048)
    val value = varchar("val", 2048)
}

object AuthenticationHolderScopes : Table("authentication_holder_scope") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id)
    val scope = varchar("scope", 2048)
}

object AuthenticationHolderRequestParameters : Table("authentication_holder_request_parameter") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id)
    val param = varchar("param", 2048)
    val value = varchar("val", 2048)
}
