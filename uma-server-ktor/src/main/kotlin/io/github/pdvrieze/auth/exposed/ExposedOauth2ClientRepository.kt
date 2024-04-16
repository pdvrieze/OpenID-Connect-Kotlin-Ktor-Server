package io.github.pdvrieze.auth.exposed

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTParser
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.selectAll
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.ClientDetailsEntity.*
import org.mitre.oauth2.model.PKCEAlgorithm
import org.mitre.oauth2.model.convert.JWSAlgorithmStringConverter
import org.mitre.oauth2.repository.OAuth2ClientRepository
import java.util.*
import kotlin.collections.HashSet

class ExposedOauth2ClientRepository(database: Database): RepositoryBase(database, ClientDetails), OAuth2ClientRepository {
    override fun getById(id: Long): ClientDetailsEntity? = transaction {
        ClientDetails.selectAll().where { ClientDetails.id eq id }.singleOrNull()?.toClient()
    }

    override fun getClientByClientId(clientId: String): ClientDetailsEntity? = transaction {
        ClientDetails.selectAll().where { ClientDetails.clientId eq clientId }
            .singleOrNull()?.toClient()
    }

    override fun saveClient(client: ClientDetailsEntity): ClientDetailsEntity {
        TODO("not implemented")
    }

    override fun deleteClient(client: ClientDetailsEntity) {
        TODO("not implemented")
    }

    override fun updateClient(id: Long, client: ClientDetailsEntity): ClientDetailsEntity {
        TODO("not implemented")
    }

    override val allClients: Collection<ClientDetailsEntity>
        get() = TODO("not implemented")
}

private fun ResultRow.toClient(): ClientDetailsEntity {
    val id = get(ClientDetails.id).value

    val redirectUris = ClientRedirectUris.selectAll().where { ClientRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientRedirectUris.redirectUri] }

    val contacts = ClientContacts.selectAll().where { ClientContacts.ownerId eq id }
        .mapTo(HashSet()) { it[ClientContacts.contact] }

    val scope = ClientScopes.selectAll().where { ClientScopes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientScopes.scope]}

    val grantTypes = ClientGrantTypes.selectAll().where { ClientGrantTypes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientGrantTypes.grantType] }

    val responseTypes = ClientResponseTypes.selectAll().where { ClientResponseTypes.ownerId eq id }
        .mapTo(HashSet()) { it[ClientResponseTypes.responseType] }

    val defaultACRvalues = ClientDefaultAcrValues.selectAll().where { ClientDefaultAcrValues.ownerId eq id }
        .mapTo(HashSet()) { it[ClientDefaultAcrValues.defaultAcrValue] }

    val postLogoutRedirectUris = ClientPostLogoutRedirectUris.selectAll()
        .where { ClientPostLogoutRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientPostLogoutRedirectUris.postLogoutRedirectUri]}

    val requestUris = ClientRequestUris.selectAll().where { ClientRequestUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientRequestUris.requestUri] }

    val claimsRedirectUris = ClientClaimsRedirectUris.selectAll()
        .where { ClientClaimsRedirectUris.ownerId eq id }
        .mapTo(HashSet()) { it[ClientClaimsRedirectUris.redirectUri] }

    val r = this
    with (ClientDetails) {
        return ClientDetailsEntity(
            id = id,
            clientId = r[clientId],
            clientSecret = r[clientSecret],
            redirectUris = redirectUris.toHashSet(),
            clientName = r[clientName],
            clientUri = r[clientUri],
            logoUri = r[logoUri],
            contacts = contacts,
            tosUri = r[tosUri],
            tokenEndpointAuthMethod = r[tokenEndpointAuthMethod]?.let { AuthMethod.getByValue(it) } ?: AuthMethod.SECRET_BASIC,
            scope = scope,
            grantTypes = grantTypes,
            responseTypes = responseTypes,
            policyUri = r[policyUri],
            jwksUri = r[jwksUri],
            jwks = r[jwks]?.let { JWKSet.parse(it) },
            softwareId = r[softwareId],
            softwareVersion = r[softwareVersion],
            applicationType = AppType.valueOf(r[applicationType]),
            sectorIdentifierUri = r[sectorIdentifierUri],
            subjectType = r[subjectType]?.let { SubjectType.getByValue(it) },
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
        )
    }
}
