package io.github.pdvrieze.auth.exposed

import io.github.pdvrieze.auth.exposed.AuthenticationHolderExtensions.references
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

object Addresses : LongIdTable("address") {
    val formatted = varchar("formatted", 256).nullable()
    val streetAddress = varchar("street_address", 256).nullable()
    val locality = varchar("locality", 256).nullable()
    val region = varchar("region", 256).nullable()
    val postalCode = varchar("postal_code", 256).nullable()
    val country = varchar("country", 256).nullable()
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

object AuthenticationHolders : LongIdTable("authentication_holder") {
    val userAuthId = long("user_auth_id").nullable() // TODO add foreign key
    val approved = bool("approved").nullable()
    val redirectUri = varchar("redirect_uri", 2048).nullable()
    val clientId = varchar("client_id", 256).nullable()
}

object AuthenticationHolderAuthorities : Table("authentication_holder_authority") {
    val ownerId = long("owner_id").references(AuthenticationHolders.id) // TODO add foreign key
    val authority = varchar("authority", 256).nullable()
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

object SavedUserAuths : LongIdTable("saved_user_auth") {
    val name = varchar("name", 1024).nullable()
    val authenticated = bool("authenticated").default(false)
    val sourceClass = varchar("source_class", 2048).nullable()
}

object SavedUserAuthAuthorities : Table("saved_user_auth_authority") {
    val ownerId = long("owner_id").references(SavedUserAuths.id)
    val authority = varchar("authority", 256).nullable()
}

object ClientAuthorities : Table("client_authority") {
    val ownerId = long("owner_id").nullable() // TODO add foreign key
    val authority = varchar("authority", 256).nullable()
}

object AuthorizationCodes : LongIdTable("authorization_code") {
    val code = varchar("code", 256).nullable()
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id).nullable()
    val expiration = timestamp("expiration").nullable().default(null)
}

object ClientGrantTypes : Table("client_grant_type") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val grantType = varchar("grant_type", 2000)
}

object ClientResponseTypes : Table("client_response_type") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val responseType = varchar("response_type", 2000)
}

object BlacklistedSites : LongIdTable("blacklisted_site") {
    val uri = varchar("uri", 2048).nullable()
}

object ClientDetails : LongIdTable("client_details") {

    val clientDescription = varchar("client_description", 1024).nullable()
    val reuseRefreshTokens = bool("reuse_refresh_tokens").default(true)
    val dynamicallyRegistered = bool("dynamically_registered").default(false)
    val allowIntrospection = bool("allow_introspection").default(false)
    val idTokenValiditySeconds = integer("id_token_validity_seconds").default(600)
    val deviceCodeValiditySeconds = integer("device_code_validity_seconds").nullable()

    val clientId = varchar("client_id", 256).uniqueIndex()
    val clientSecret = varchar("client_secret", 2048).nullable()
    val accessTokenValiditySeconds = long("access_token_validity_seconds").nullable()
    val refreshTokenValiditySeconds = long("refresh_token_validity_seconds").nullable()

    val applicationType = varchar("application_type", 256).default("web")
    val clientName = varchar("client_name", 256).nullable()
    val tokenEndpointAuthMethod = varchar("token_endpoint_auth_method", 256).nullable()
    val subjectType = varchar("subject_type", 256).nullable()

    val logoUri = varchar("logo_uri", 2048).nullable()
    val policyUri = varchar("policy_uri", 2048).nullable()
    val clientUri = varchar("client_uri", 2048).nullable()
    val tosUri = varchar("tos_uri", 2048).nullable()

    val jwksUri = varchar("jwks_uri", 2048).nullable()
    val jwks = varchar("jwks", 8192).nullable()
    val sectorIdentifierUri = varchar("sector_identifier_uri", 2048).nullable()

    val requestObjectSigningAlg = varchar("request_object_signing_alg", 256).nullable()

    val userInfoSignedResponseAlg = varchar("user_info_signed_response_alg", 256).nullable()
    val userInfoEncryptedResponseAlg = varchar("user_info_encrypted_response_alg", 256).nullable()
    val userInfoEncryptedResponseEnc = varchar("user_info_encrypted_response_enc", 256).nullable()

    val idTokenSignedResponseAlg = varchar("id_token_signed_response_alg", 256).nullable()
    val idTokenEncryptedResponseAlg = varchar("id_token_encrypted_response_alg", 256).nullable()
    val idTokenEncryptedResponseEnc = varchar("id_token_encrypted_response_enc", 256).nullable()

    val tokenEndpointAuthSigningAlg = varchar("token_endpoint_auth_signing_alg", 256).nullable()

    val defaultMaxAge = long("default_max_age").nullable()
    val requireAuthTime = bool("require_auth_time").nullable()
    val createdAt = timestamp("created_at").nullable().default(null)
    val initiateLoginUri = varchar("initiate_login_uri", 2048).nullable()
    val clearAccessTokensOnRefresh = bool("clear_access_tokens_on_refresh").default(true)

    val softwareStatement = varchar("software_statement", 4096).nullable()
    val softwareId = varchar("software_id", 2048).nullable()
    val softwareVersion = varchar("software_version", 2048).nullable()

    val codeChallengeMethod = varchar("code_challenge_method", 256).nullable()
}

object ClientRequestUris : Table("client_request_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val requestUri = varchar("request_uri", 2000)
}

object ClientPostLogoutRedirectUris : Table("client_post_logout_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val postLogoutRedirectUri = varchar("post_logout_redirect_uri", 2000)
}

object ClientDefaultAcrValues : Table("client_default_acr_value") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val defaultAcrValue = varchar("default_acr_value", 2000)
}

object ClientContacts : Table("client_contact") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val contact = varchar("contact", 256)
}

object ClientRedirectUris : Table("client_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val redirectUri = varchar("redirect_uri", 2048)
}

object ClientClaimsRedirectUris : Table("client_claims_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val redirectUri = varchar("redirect_uri", 2048)
}

object RefreshTokens : LongIdTable("refresh_token") {
    val tokenValue = varchar("token_value", 4096).uniqueIndex()
    val expiration = timestamp("expiration").nullable().default(null)
    val authHolderId = long("auth_holder_id").references(AuthenticationHolders.id)
    val clientId = long("client_id").references(ClientDetails.id).nullable()
}

object ClientResources : Table("client_resource") {
    val ownerId = long("owner_id") // TODO add foreign key
    val resourceId = varchar("resource_id", 256)
}

object ClientScopes : Table("client_scope") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val scope = varchar("scope", 2048)
}

object TokenScopes : Table("token_scope") {
    val ownerId = long("owner_id").nullable() // TODO add foreign key
    val scope = varchar("scope", 2048)
}

object SystemScopes : LongIdTable("system_scope") {
    val value = varchar("scope", 256).uniqueIndex()
    val description = varchar("description", 4096).nullable()
    val icon = varchar("icon", 256).nullable()
    val restricted = bool("restricted").default(false)
    val defaultScope = bool("default_scope").default(false)
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

object WhitelistedSites : LongIdTable("whitelisted_site") {
    val creatorUserId = varchar("creator_user_id", 256).nullable()
    val clientId = varchar("client_id", 256).nullable()
}

object WhitelistedSiteScopes : Table("whitelisted_site_scope") {
    val ownerId = long("owner_id").references(WhitelistedSites.id)
    val scope = varchar("scope", 256)
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
    val owner = varchar("owner", 256)
    val clientId = varchar("client_id", 256).references(ClientDetails.clientId).nullable()
}

object ResourceSetScopes : Table("resource_set_scope") {
    val ownerId = long("owner_id") // TODO add foreign key
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
    val ownerId = long("owner_id") // TODO add foreign key
    val scope = varchar("scope", 256)
}

object Claims : LongIdTable("claim") {
    val name = varchar("name", 256).nullable()
    val friendlyName = varchar("friendly_name", 1024).nullable()
    val claimType = varchar("claim_type", 1024).nullable()
    val claimValue = varchar("claim_value", 1024).nullable()
}

object ClaimToPolicys : Table("claim_to_policy") {
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
    val ownerId = long("owner_id") // TODO add foreign key
    val scope = varchar("scope", 256)
}

object ClaimTokenFormats : Table("claim_token_format") {
    val ownerId = long("owner_id") // TODO add foreign key
    val claimTokenFormat = varchar("claim_token_format", 1024)
}

object ClaimIssuerss : Table("claim_issuer") {
    val ownerId = long("owner_id") // TODO add foreign key
    val issuer = varchar("issuer", 1024).nullable()
}

object SavedRegisteredClients : LongIdTable("saved_registered_client") {
    val issuer = varchar("issuer", 1024).nullable()
    val registeredClient = varchar("registered_client", 8192).nullable()
}

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
