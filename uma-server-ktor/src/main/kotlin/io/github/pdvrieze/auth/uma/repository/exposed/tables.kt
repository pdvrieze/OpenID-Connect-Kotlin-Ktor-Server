package io.github.pdvrieze.auth.uma.repository.exposed

import io.github.pdvrieze.auth.repository.exposed.ClientDetails
import io.github.pdvrieze.auth.repository.exposed.Permissions
import io.github.pdvrieze.auth.repository.exposed.ResourceSets
import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp


object Addresses : LongIdTable("address") {
    val formatted = varchar("formatted", 256).nullable()
    val streetAddress = varchar("street_address", 256).nullable()
    val locality = varchar("locality", 256).nullable()
    val region = varchar("region", 256).nullable()
    val postalCode = varchar("postal_code", 256).nullable()
    val country = varchar("country", 256).nullable()
}

object ClientAuthorities : Table("client_authority") {
    val ownerId = long("owner_id").nullable() // TODO add foreign key
    val authority = varchar("authority", 256).nullable()
}


object BlacklistedSites : LongIdTable("blacklisted_site") {
    val uri = varchar("uri", 2048)
}



object ClientResources : Table("client_resource") {
    val ownerId = long("owner_id").references(ClientDetails.id) // TODO add foreign key
    val resourceId = varchar("resource_id", 256)
}

object UserInfos : LongIdTable("user_info") {
    val sub = varchar("sub", 256).nullable()
    val preferredUsername = varchar("preferred_username", 256).nullable()
    val name = varchar("name", 256).nullable()
    val givenName = varchar("given_name", 256).nullable()
    val familyName = varchar("family_name", 256).nullable()
    val middleName = varchar("middle_name", 256).nullable()
    val nickname = varchar("nickname", 256).nullable()
    val profile = varchar("profile", 256).nullable()
    val picture = varchar("picture", 256).nullable()
    val website = varchar("website", 256).nullable()
    val email = varchar("email", 256).nullable()
    val emailVerified = bool("email_verified").nullable()
    val gender = varchar("gender", 256).nullable()
    val zoneInfo = varchar("zone_info", 256).nullable()
    val locale = varchar("locale", 256).nullable()
    val phoneNumber = varchar("phone_number", 256).nullable()
    val phoneNumberVerified = bool("phone_number_verified").nullable()
    val addressId = varchar("address_id", 256).nullable()
    val updatedTime = varchar("updated_time", 256).nullable()
    val birthdate = varchar("birthdate", 256).nullable()
    val src = varchar("src", 4096).nullable()
}

object PairwiseIdentifiers : LongIdTable("pairwise_identifier") {
    val identifier = varchar("identifier", 256).nullable()
    val sub = varchar("sub", 256).nullable()
    val sectorIdentifier = varchar("sector_identifier", 2048).nullable()
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

object PermissionTickets : LongIdTable("permission_ticket") {
    val ticket = varchar("ticket", 256)
    val permissionId = long("permission_id").references(Permissions.id)
    val expiration = timestamp("expiration").nullable().default(null)
}

object Permissions : LongIdTable("permission") {
    val resourceSetId = long("resource_set_id").references(ResourceSets.id).nullable()
}

object PermissionScopes : Table("permission_scope") {
    val ownerId = long("owner_id").references(Permissions.id)
    val scope = varchar("scope", 256)
}

object Claims : LongIdTable("claim") {
    val name = varchar("name", 256).nullable()
    val friendlyName = varchar("friendly_name", 1024).nullable()
    val claimType = varchar("claim_type", 1024).nullable()
    val claimValue = varchar("claim_value", 1024).nullable()
}

object ClaimToPolicies : Table("claim_to_policy") {
    val policyId = long("policy_id").references(Policies.id)
    val claimId = long("claim_id").references(Claims.id)
}

object ClaimToPermissionTickets : Table("claim_to_permission_ticket") {
    val permissionTicketId = long("permission_ticket_id").references(PermissionTickets.id)
    val claimId = long("claim_id").references(Claims.id)
}

object Policies : LongIdTable("policy") {
    val name = varchar("name", 1024).nullable()
    val resourceSetId = long("resource_set_id").references(ResourceSets.id).nullable()
}

object PolicyScopes : Table("policy_scope") {
    val ownerId = long("owner_id").references(Policies.id)
    val scope = varchar("scope", 256)
}

object ClaimTokenFormats : Table("claim_token_format") {
    val ownerId = long("owner_id").references(Claims.id)
    val claimTokenFormat = varchar("claim_token_format", 1024)
}

object ClaimIssuers : Table("claim_issuer") {
    val ownerId = long("owner_id").references(Claims.id)
    val issuer = varchar("issuer", 1024)
}

object SavedRegisteredClients : LongIdTable("saved_registered_client") {
    val issuer = varchar("issuer", 1024).nullable()
    val registeredClient = varchar("registered_client", 8192)
}

