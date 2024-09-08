package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp


object AccessTokens : LongIdTable("access_token") {
    val tokenValue = varchar("token_value", 4096)
    val expiration = timestamp("expiration").nullable().default(null)
    val tokenType = varchar("token_type", 256).nullable()
    val refreshTokenId = long("refresh_token_id").references(RefreshTokens.id)
    val clientId = long("client_id").references(ClientDetails.id).nullable()
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id)
    val approvedSiteId = long("approved_site_id").references(ApprovedSites.id).nullable()
}

object AccessTokenPermissions : Table("access_token_permissions") {
    val accessTokenId = long("access_token_id").references(AccessTokens.id)
    val permissionId = long("permission_id").references(Permissions.id)
}

object RefreshTokens : LongIdTable("refresh_token") {
    val tokenValue = varchar("token_value", 4096).uniqueIndex()
    val expiration = timestamp("expiration").nullable().default(null)
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id)
    val clientId = long("client_id").references(ClientDetails.id).nullable()
}

object ApprovedSites : LongIdTable("approved_site") {
    val userId = varchar("user_id", 256).nullable() // TODO add foreign key
    val clientId = varchar("client_id", 256).references(ClientDetails.clientId).nullable()
    val creationDate = timestamp("creation_date").nullable().default(null)
    val accessDate = timestamp("access_date").nullable().default(null)
    val timeoutDate = timestamp("timeout_date").nullable().default(null)
    val whitelistedSiteId = long("whitelisted_site_id").references(WhitelistedSites.id).nullable()
}

object ApprovedSiteScopes : Table("approved_site_scope") {
    val ownerId = long("owner_id").references(ApprovedSites.id)
    val scope = varchar("scope", 256)
}

object WhitelistedSites : LongIdTable("whitelisted_site") {
    val creatorUserId = varchar("creator_user_id", 256).nullable()
    val clientId = varchar("client_id", 256).nullable()
}

object WhitelistedSiteScopes : Table("whitelisted_site_scope") {
    val ownerId = long("owner_id").references(WhitelistedSites.id)
    val scope = varchar("scope", 256)
}

object Permissions : LongIdTable("permission") {
    val resourceSetId = long("resource_set_id").references(ResourceSets.id).nullable()
}

object ResourceSets : LongIdTable("resource_set") {
    val name = varchar("name", 1024)
    val uri = varchar("uri", 1024).nullable()
    val iconUri = varchar("icon_uri", 1024).nullable()
    val rsType = varchar("rs_type", 256).nullable()
    val owner = varchar("owner", 256).index()
    val clientId = varchar("client_id", 256).references(ClientDetails.clientId).nullable()
}

object ResourceSetScopes : Table("resource_set_scope") {
    val ownerId = long("owner_id").references(ResourceSets.id)
    val scope = varchar("scope", 256)
}

object TokenScopes : Table("token_scope") {
    val ownerId = long("owner_id").nullable() // TODO add foreign key
    val scope = varchar("scope", 2048)
}

