package io.github.pdvrieze.auth.repository.exposed

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTParser
import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.statements.UpdateBuilder
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.repository.OAuth2ClientRepository
import java.util.*

class ExposedOauth2ClientRepository(database: Database) :
    RepositoryBase(
        database,
        ClientDetails,
        ClientRedirectUris,
        ClientRequestUris,
        ClientContacts,
        ClientScopes,
        ClientGrantTypes,
        ClientResponseTypes,
        ClientDefaultAcrValues,
        ClientPostLogoutRedirectUris,
        ClientRequestUris,
        ClientClaimsRedirectUris,
    ), OAuth2ClientRepository {

    override fun getById(id: Long): OAuthClientDetails? = transaction {
        ClientDetails.selectAll().where { ClientDetails.id eq id }.singleOrNull()?.toClient()
    }

    override fun getClientByClientId(clientId: String): OAuthClientDetails? = transaction {
        ClientDetails.selectAll().where { ClientDetails.clientId eq clientId }
            .singleOrNull()?.toClient()
    }

    override fun saveClient(client: OAuthClientDetails): OAuthClientDetails = transaction {
        val oldId = client.id
        val newId = ClientDetails.save(client.id) { client.toUpdate(it) }

        if (oldId!= null) { // update
            deleteJoinedTables(oldId)
        }

        client.requestUris?.let { l ->
            ClientRequestUris.batchInsert(l) { uri ->
                this[ClientRequestUris.ownerId] = newId
                this[ClientRequestUris.requestUri] = uri
            }
        }

        ClientRedirectUris.batchInsert(client.redirectUris) { uri ->
            this[ClientRedirectUris.ownerId] = newId
            this[ClientRedirectUris.redirectUri] = uri
        }

        client.contacts?.let { l ->
            ClientContacts.batchInsert(l) { contact ->
                this[ClientContacts.ownerId] = newId
                this[ClientContacts.contact] = contact
            }
        }

        client.scope?.let { s ->
            ClientScopes.batchInsert(s) { scope ->
                this[ClientScopes.ownerId] = newId
                this[ClientScopes.scope] = scope
            }
        }

        ClientGrantTypes.batchInsert(client.authorizedGrantTypes) { grantType ->
            this[ClientGrantTypes.ownerId] = newId
            this[ClientGrantTypes.grantType] = grantType
        }

        client.contacts?.let { l ->
            ClientContacts.batchInsert(l) { responseType ->
                this[ClientResponseTypes.ownerId] = newId
                this[ClientResponseTypes.responseType] = responseType
            }
        }

        client.defaultACRvalues?.let { l ->
            ClientDefaultAcrValues.batchInsert(l) { responseType ->
                this[ClientDefaultAcrValues.ownerId] = newId
                this[ClientDefaultAcrValues.defaultAcrValue] = responseType
            }
        }

        client.postLogoutRedirectUris?.let { l ->
            ClientPostLogoutRedirectUris.batchInsert(l) { postLogoutRedirectUri ->
                this[ClientPostLogoutRedirectUris.ownerId] = newId
                this[ClientPostLogoutRedirectUris.postLogoutRedirectUri] = postLogoutRedirectUri
            }
        }

        client.requestUris?.let { l ->
            ClientRequestUris.batchInsert(l) { requestUri ->
                this[ClientRequestUris.ownerId] = newId
                this[ClientRequestUris.requestUri] = requestUri
            }
        }

        ClientClaimsRedirectUris.batchInsert(client.redirectUris) { redirectUri ->
            this[ClientClaimsRedirectUris.ownerId] = newId
            this[ClientClaimsRedirectUris.redirectUri] = redirectUri
        }

        client.withId(newId)
    }

    override fun deleteClient(client: OAuthClientDetails): Unit = transaction {
        val clientId = requireNotNull(client.id)
        deleteJoinedTables(clientId)
        ClientDetails.deleteWhere { id eq clientId }
    }

    override fun updateClient(id: Long, client: OAuthClientDetails): OAuthClientDetails {
        require(client.id == id)
        return saveClient(client)
    }

    override val allClients: Collection<OAuthClientDetails>
        get() = transaction {
            ClientDetails.selectAll().map { it.toClient() }
        }

    private fun deleteJoinedTables(clientId: Long) {
        ClientRedirectUris.deleteWhere { ownerId eq clientId }
        ClientRequestUris.deleteWhere { ownerId eq clientId }
        ClientContacts.deleteWhere { ownerId eq clientId }
        ClientScopes.deleteWhere { ownerId eq clientId }
        ClientGrantTypes.deleteWhere { ownerId eq clientId }
        ClientResponseTypes.deleteWhere { ownerId eq clientId }
        ClientDefaultAcrValues.deleteWhere { ownerId eq clientId }
        ClientPostLogoutRedirectUris.deleteWhere { ownerId eq clientId }
        ClientRequestUris.deleteWhere { ownerId eq clientId }
        ClientClaimsRedirectUris.deleteWhere { ownerId eq clientId }
    }
}

private fun OAuthClientDetails.toUpdate(builder: UpdateBuilder<Int>) {
    val t = ClientDetails
    id?.let { builder[t.id] = it }

    builder[ClientDetails.clientId] = clientId
    builder[ClientDetails.clientSecret] = clientSecret
    builder[ClientDetails.clientName] = clientName
    builder[ClientDetails.clientUri] = clientUri
    builder[ClientDetails.logoUri] = logoUri
    builder[ClientDetails.tosUri] = tosUri
    builder[ClientDetails.tokenEndpointAuthMethod] = tokenEndpointAuthMethod?.value
    builder[ClientDetails.policyUri] = policyUri
    builder[ClientDetails.jwksUri] = jwksUri
    builder[ClientDetails.jwks] = jwks?.toString()
    builder[ClientDetails.softwareId] = softwareId
    builder[ClientDetails.softwareVersion] = softwareVersion
    builder[ClientDetails.applicationType] = applicationType.value
    builder[ClientDetails.sectorIdentifierUri] = sectorIdentifierUri
    builder[ClientDetails.subjectType] = subjectType?.value
    builder[ClientDetails.requestObjectSigningAlg] = requestObjectSigningAlg?.name
    builder[ClientDetails.userInfoSignedResponseAlg] = userInfoSignedResponseAlg?.name
    builder[ClientDetails.userInfoEncryptedResponseAlg] = userInfoEncryptedResponseAlg?.name
    builder[ClientDetails.userInfoEncryptedResponseEnc] = userInfoEncryptedResponseEnc?.name
    builder[ClientDetails.idTokenSignedResponseAlg] = idTokenSignedResponseAlg?.name
    builder[ClientDetails.idTokenEncryptedResponseAlg] = idTokenEncryptedResponseAlg?.name
    builder[ClientDetails.idTokenEncryptedResponseEnc] = idTokenEncryptedResponseEnc?.name
    builder[ClientDetails.tokenEndpointAuthSigningAlg] = tokenEndpointAuthSigningAlg?.name
    builder[ClientDetails.defaultMaxAge] = defaultMaxAge
    builder[ClientDetails.requireAuthTime] = requireAuthTime
    builder[ClientDetails.initiateLoginUri] = initiateLoginUri
    builder[ClientDetails.clientDescription] = clientDescription.takeIf(String::isNotBlank)
    builder[ClientDetails.reuseRefreshTokens] = isReuseRefreshToken
    builder[ClientDetails.dynamicallyRegistered] = isDynamicallyRegistered
    builder[ClientDetails.allowIntrospection] = isAllowIntrospection
    builder[ClientDetails.accessTokenValiditySeconds] = accessTokenValiditySeconds?.toLong()
    builder[ClientDetails.refreshTokenValiditySeconds] = refreshTokenValiditySeconds?.toLong()
    builder[ClientDetails.idTokenValiditySeconds] = idTokenValiditySeconds ?: -1
    builder[ClientDetails.createdAt] = createdAt?.toInstant()
    builder[ClientDetails.clearAccessTokensOnRefresh] = isClearAccessTokensOnRefresh
    builder[ClientDetails.deviceCodeValiditySeconds] = deviceCodeValiditySeconds
    builder[ClientDetails.softwareStatement] = softwareStatement?.serialize()
    builder[ClientDetails.codeChallengeMethod] = codeChallengeMethod?.name
}

private fun ResultRow.toClient(): OAuthClientDetails {
    val id = get(ClientDetails.id).value

    val redirectUris = ClientRedirectUris.selectAll().where { ClientRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientRedirectUris.redirectUri] }

    val contacts = ClientContacts.selectAll().where { ClientContacts.ownerId eq id }
        .mapTo(HashSet()) { it[ClientContacts.contact] }

    val scope = ClientScopes.selectAll().where { ClientScopes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientScopes.scope] }

    val grantTypes = ClientGrantTypes.selectAll().where { ClientGrantTypes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientGrantTypes.grantType] }

    val responseTypes = ClientResponseTypes.selectAll().where { ClientResponseTypes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientResponseTypes.responseType] }

    val defaultACRvalues = ClientDefaultAcrValues.selectAll().where { ClientDefaultAcrValues.ownerId eq id }
        .mapTo(HashSet()) { it[ClientDefaultAcrValues.defaultAcrValue] }

    val postLogoutRedirectUris = ClientPostLogoutRedirectUris.selectAll()
        .where { ClientPostLogoutRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientPostLogoutRedirectUris.postLogoutRedirectUri] }

    val requestUris = ClientRequestUris.selectAll().where { ClientRequestUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientRequestUris.requestUri] }

    val claimsRedirectUris = ClientClaimsRedirectUris.selectAll()
        .where { ClientClaimsRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientClaimsRedirectUris.redirectUri] }

    val r = this
    with(ClientDetails) {
        return ClientDetailsEntity.Builder(
            id = id,
            clientId = r[clientId],
            clientSecret = r[clientSecret],
            redirectUris = redirectUris.toHashSet(),
            clientName = r[clientName],
            clientUri = r[clientUri],
            logoUri = r[logoUri],
            contacts = contacts,
            tosUri = r[tosUri],
            tokenEndpointAuthMethod = r[tokenEndpointAuthMethod]?.let { OAuthClientDetails.AuthMethod.getByValue(it) }
                ?: OAuthClientDetails.AuthMethod.SECRET_BASIC,
            scope = scope,
            authorizedGrantTypes = grantTypes,
            responseTypes = responseTypes,
            policyUri = r[policyUri],
            jwksUri = r[jwksUri],
            jwks = r[jwks]?.let { JWKSet.parse(it) },
            softwareId = r[softwareId],
            softwareVersion = r[softwareVersion],
            applicationType = OAuthClientDetails.AppType.getByValue(r[applicationType])
                ?: OAuthClientDetails.AppType.WEB,
            sectorIdentifierUri = r[sectorIdentifierUri],
            subjectType = r[subjectType]?.let { OAuthClientDetails.SubjectType.getByValue(it) },
            requestObjectSigningAlg = r[requestObjectSigningAlg]?.let { JWSAlgorithm.parse(it) },
            userInfoSignedResponseAlg = r[userInfoSignedResponseAlg]?.let { JWSAlgorithm.parse(it) },
            userInfoEncryptedResponseAlg = r[userInfoEncryptedResponseAlg]?.let { JWEAlgorithm.parse(it) },
            userInfoEncryptedResponseEnc = r[userInfoEncryptedResponseEnc]?.let { EncryptionMethod.parse(it) },
            idTokenSignedResponseAlg = r[idTokenSignedResponseAlg]?.let { JWSAlgorithm.parse(it) },
            idTokenEncryptedResponseAlg = r[idTokenEncryptedResponseAlg]?.let { JWEAlgorithm.parse(it) },
            idTokenEncryptedResponseEnc = r[idTokenEncryptedResponseEnc]?.let { EncryptionMethod.parse(it) },
            tokenEndpointAuthSigningAlg = r[tokenEndpointAuthSigningAlg]?.let { JWSAlgorithm.parse(it) },
            defaultMaxAge = r[defaultMaxAge],
            requireAuthTime = r[requireAuthTime],
            defaultACRvalues = defaultACRvalues,
            initiateLoginUri = r[initiateLoginUri],
            postLogoutRedirectUris = postLogoutRedirectUris,
            requestUris = requestUris,
            clientDescription = r[clientDescription] ?: "",
            isReuseRefreshToken = r[reuseRefreshTokens],
            isDynamicallyRegistered = r[dynamicallyRegistered],
            isAllowIntrospection = r[allowIntrospection],
            idTokenValiditySeconds = r[idTokenValiditySeconds],
            createdAt = r[createdAt]?.let { Date.from(it) },
            isClearAccessTokensOnRefresh = r[clearAccessTokensOnRefresh],
            deviceCodeValiditySeconds = r[deviceCodeValiditySeconds],
            claimsRedirectUris = claimsRedirectUris,
            softwareStatement = r[softwareStatement]?.let { JWTParser.parse(it) },
            codeChallengeMethod = r[codeChallengeMethod]?.let { PKCEAlgorithm.parse(it) },
            accessTokenValiditySeconds = r[accessTokenValiditySeconds]?.toInt(),
            refreshTokenValiditySeconds = r[refreshTokenValiditySeconds]?.toInt(),
        ).build()
    }
}
