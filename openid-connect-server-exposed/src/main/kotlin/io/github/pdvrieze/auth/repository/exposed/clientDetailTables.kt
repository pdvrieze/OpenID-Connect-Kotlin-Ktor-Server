package io.github.pdvrieze.auth.repository.exposed

import org.jetbrains.exposed.dao.id.LongIdTable
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp

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

object ClientClaimsRedirectUris : Table("client_claims_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val redirectUri = varchar("redirect_uri", 2048)
}

object ClientContacts : Table("client_contact") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val contact = varchar("contact", 256)
}

object ClientDefaultAcrValues : Table("client_default_acr_value") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val defaultAcrValue = varchar("default_acr_value", 2000)
}

object ClientGrantTypes : Table("client_grant_type") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val grantType = varchar("grant_type", 2000)
}

object ClientPostLogoutRedirectUris : Table("client_post_logout_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val postLogoutRedirectUri = varchar("post_logout_redirect_uri", 2000)
}

object ClientRedirectUris : Table("client_redirect_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val redirectUri = varchar("redirect_uri", 2048)
}

object ClientRequestUris : Table("client_request_uri") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val requestUri = varchar("request_uri", 2000)
}

object ClientResponseTypes : Table("client_response_type") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val responseType = varchar("response_type", 2000)
}

object ClientScopes : Table("client_scope") {
    val ownerId = long("owner_id").references(ClientDetails.id)
    val scope = varchar("scope", 2048)
}
