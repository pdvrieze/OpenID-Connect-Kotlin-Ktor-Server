package io.github.pdvrieze.auth.repository.exposed

import com.nimbusds.jwt.JWTParser
import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.ClientDetailsEntity
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2AccessTokenEntity
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.OAuth2ClientRepository
import org.mitre.oauth2.repository.OAuth2TokenRepository
import org.mitre.openid.connect.model.ApprovedSite
import org.mitre.uma.model.ResourceSet
import org.mitre.util.getLogger
import java.text.ParseException
import java.time.Instant
import java.util.*

class ExposedOauth2TokenRepository(
    database: Database,
    val authenticationHolderRepository: AuthenticationHolderRepository,
    val clientRepository: OAuth2ClientRepository,
) : RepositoryBase(database, AccessTokens, RefreshTokens, SavedUserAuths, SavedUserAuthAuthorities, TokenScopes),
    OAuth2TokenRepository {

    override fun getRefreshTokenByValue(refreshTokenValue: String): OAuth2RefreshTokenEntity? = transaction {
        RefreshTokens.selectAll()
            .where { RefreshTokens.tokenValue eq refreshTokenValue }
            .singleOrNull()
            ?.toOAuthRefeshToken()
    }

    override fun getRefreshTokenById(id: Long): OAuth2RefreshTokenEntity? = transaction {
        RefreshTokens.selectAll()
            .where { RefreshTokens.id eq id }
            .singleOrNull()
            ?.toOAuthRefeshToken()
    }

    override fun getRefreshTokensByUserName(name: String): Set<OAuth2RefreshTokenEntity> = transaction {
        (RefreshTokens.innerJoin(AuthenticationHolders innerJoin SavedUserAuths))
            .select(RefreshTokens.columns)
            .where { SavedUserAuths.name eq name }
            .mapTo(HashSet()) { it.toOAuthRefeshToken() }
    }

    override fun getRefreshTokensForClient(client: OAuthClientDetails): List<OAuth2RefreshTokenEntity> {
        val clientId = client.id ?: return emptyList()
        return transaction {
            RefreshTokens.selectAll()
                .where { RefreshTokens.clientId eq clientId }
                .map { it.toOAuthRefeshToken() }
        }
    }

    override val allRefreshTokens: Set<OAuth2RefreshTokenEntity>
        get() = transaction {
            RefreshTokens.selectAll().mapTo(HashSet()) { it.toOAuthRefeshToken() }
        }

    override val allExpiredRefreshTokens: Set<OAuth2RefreshTokenEntity>
        get() = transaction {
            RefreshTokens.selectAll()
                .where { RefreshTokens.expiration lessEq Instant.now() }
                .mapTo(HashSet()) { it.toOAuthRefeshToken() }
        }

    override fun getAllExpiredRefreshTokens(pageCriteria: PageCriteria): Set<OAuth2RefreshTokenEntity> = transaction {
        RefreshTokens.selectAll()
            .where { RefreshTokens.expiration lessEq Instant.now() }
            .limit(pageCriteria.pageSize, pageCriteria.pageNumber.toLong() * pageCriteria.pageSize)
            .mapTo(HashSet()) { it.toOAuthRefeshToken() }
    }

    override fun removeRefreshToken(refreshToken: OAuth2RefreshTokenEntity) {
        val tokenId = refreshToken.id ?: return // does not exist in the database

        return transaction {
            AccessTokens.deleteWhere { refreshTokenId eq tokenId }
            RefreshTokens.deleteWhere { id eq tokenId }
        }
    }

    override fun saveRefreshToken(refreshToken: OAuth2RefreshTokenEntity): OAuth2RefreshTokenEntity = transaction {
        with (RefreshTokens) {
            val newId = RefreshTokens.save(refreshToken.id) { b ->
                b[authHolderId] = requireNotNull(refreshToken.authenticationHolder.id)
                b[clientId] = refreshToken.client?.id
                b[tokenValue] = refreshToken.jwt.serialize()
                b[expiration] = refreshToken.expiration?.toInstant()
            }
            refreshToken.apply { id = newId }
        }
    }

    @Deprecated("Not a valid operation, duplicate tokens are prevented by a unique index")
    override fun clearDuplicateRefreshTokens() {
        logger.warn("Ignored clearing of duplicate refresh tokens as they are not permitted in the schema")
    }

    override fun getAccessTokenById(id: Long): OAuth2AccessTokenEntity? = transaction {
        AccessTokens.selectAll()
            .where { AccessTokens.id eq id }
            .singleOrNull()
            ?.toOAuthAccessToken()
    }

    override fun getAccessTokenByValue(accessTokenValue: String): OAuth2AccessTokenEntity? = transaction {
        AccessTokens.selectAll()
            .where { AccessTokens.tokenValue eq accessTokenValue }
            .singleOrNull()
            ?.toOAuthAccessToken()
    }

    override fun getAccessTokensForClient(client: OAuthClientDetails): List<OAuth2AccessTokenEntity> {
        val clientId = client.id ?: return emptyList()
        return transaction {
            AccessTokens.selectAll()
                .where { AccessTokens.clientId eq clientId }
                .map { it.toOAuthAccessToken() }
        }
    }

    override fun getAccessTokensByUserName(name: String): Set<OAuth2AccessTokenEntity> = transaction {
        // select r from OAuth2AccessTokenEntity r where r.authenticationHolder.userAuth.name = :${OAuth2AccessTokenEntity.PARAM_NAME}
/*
        val t = (AccessTokens.innerJoin(AuthenticationHolders innerJoin SavedUserAuths)).selectAll().map { r ->
            r.fieldIndex.entries.joinToString { (k, _) ->
                "$k = ${r[k]}"
            }
        }
        logger.warn(t.joinToString("\n"))
*/

        (AccessTokens.innerJoin(AuthenticationHolders innerJoin SavedUserAuths))
            .select(AccessTokens.columns)
            .where { SavedUserAuths.name eq name }
            .mapTo(HashSet()) { it.toOAuthAccessToken() }
    }

    override val allAccessTokens: Set<OAuth2AccessTokenEntity>
        get() = transaction {
            AccessTokens.selectAll().mapTo(HashSet()) {
                it.toOAuthAccessToken()
            }
        }

    override val allExpiredAccessTokens: Set<OAuth2AccessTokenEntity>
        get() {
            val now = Instant.now()
            return transaction {
                AccessTokens.selectAll()
                    .where { AccessTokens.expiration lessEq now }
                    .mapTo(HashSet()) { it.toOAuthAccessToken() }
            }
        }

    override fun getAllExpiredAccessTokens(pageCriteria: PageCriteria): Set<OAuth2AccessTokenEntity> {
        val now = Instant.now()
        return transaction {
            AccessTokens.selectAll()
                .where { AccessTokens.expiration lessEq now }
                .limit(pageCriteria.pageSize, pageCriteria.pageSize.toLong() * pageCriteria.pageNumber)
                .mapTo(HashSet()) { it.toOAuthAccessToken() }
        }
    }

    override fun getAccessTokensForResourceSet(rs: ResourceSet): Set<OAuth2AccessTokenEntity> {
        val resourceSetId = rs.id ?: return emptySet()
        return transaction {
            (AccessTokens innerJoin Permissions).select(AccessTokens.columns)
                .where { Permissions.resourceSetId eq resourceSetId }
                .mapTo(HashSet()) { it.toOAuthAccessToken() }
        }
    }

    override fun getAccessTokensForApprovedSite(approvedSite: ApprovedSite): List<OAuth2AccessTokenEntity> {
        val siteId = approvedSite.id ?: return emptyList()
        return transaction {
            AccessTokens.selectAll()
                .where { AccessTokens.approvedSiteId eq siteId }
                .map { it.toOAuthAccessToken() }
        }
    }

    override fun clearAccessTokensForRefreshToken(refreshToken: OAuth2RefreshTokenEntity) {
        val refreshTokenId = refreshToken.id ?: return
        transaction {
            AccessTokens.deleteWhere { AccessTokens.refreshTokenId eq refreshTokenId }
        }
    }

    override fun removeAccessToken(accessToken: OAuth2AccessTokenEntity) {
        val tokenId = requireNotNull(accessToken.id) { "missing id in access token" }
        transaction {
            AccessTokens.deleteWhere { id eq tokenId }
        }
    }

    override fun saveAccessToken(token: OAuth2AccessTokenEntity): OAuth2AccessTokenEntity {
        val tokenId = token.id
        return transaction {
            val newId = with(AccessTokens) {
                AccessTokens.save(tokenId) { b ->
                    b[expiration] = token.expiration.toInstant()
                    b[tokenValue] = token.jwt.serialize()
                    b[clientId] = token.client?.id
                    b[authHolderId] = token.authenticationHolder.id!!
                    b[refreshTokenId] = token.refreshToken!!.id!!
                    b[tokenType] = token.tokenType

                }
            }

            TokenScopes.deleteWhere { ownerId eq tokenId }
            val scopes = token.scope
            if (scopes.isNotEmpty()) {
                TokenScopes.batchInsert(scopes) { scope ->
                    this[TokenScopes.ownerId] = newId
                    this[TokenScopes.scope] = scope
                }
            }


            token.apply { id = newId }
        }
    }

    @Deprecated("Not a valid operation, duplicate tokens are prevented by a unique index")
    override fun clearDuplicateAccessTokens() {
        logger.warn("Ignored clearing of access refresh tokens as they are not permitted in the schema")
    }

    override fun clearTokensForClient(client: OAuthClientDetails) {
        TODO("not implemented")
    }


    private fun ResultRow.toOAuthRefeshToken(): OAuth2RefreshTokenEntity {
        val r = this
        with(RefreshTokens) {
            val authenticationHolder = checkNotNull(authenticationHolderRepository.getById(r[authHolderId])) {
                "violated foreign key constraint with missing authentication holder"
            }

            val client = r[clientId]?.let { clientRepository.getById(it) } as ClientDetailsEntity?

            return OAuth2RefreshTokenEntity(
                id = r[id].value,
                authenticationHolder = authenticationHolder,
                client = client,
                jwt = JWTParser.parse(r[tokenValue]),
                expiration = r[expiration]?.let { Date.from(it) },
            )
        }

    }

    private fun ResultRow.toOAuthAccessToken(): OAuth2AccessTokenEntity {
        val r = this
        with(AccessTokens) {
            val tokenId = r[id].value

            val authenticationHolder = checkNotNull(authenticationHolderRepository.getById(r[authHolderId])) {
                "violated foreign key constraint with missing authentication holder"
            }

            val client = r[clientId]?.let { clientRepository.getById(it) } as ClientDetailsEntity?

            val refreshTokenId = r[refreshTokenId]
            val refreshToken = refreshTokenId?.let {
                checkNotNull(getRefreshTokenById(it)) {
                    "Invalid refresh token id as for access token: ${r[AccessTokens.refreshTokenId]}"
                }
            }

            val scopes = TokenScopes
                .select(TokenScopes.scope)
                .where { TokenScopes.ownerId eq tokenId }
                .mapTo(HashSet()) { it[TokenScopes.scope] }

            return OAuth2AccessTokenEntity(
                id = tokenId,
                expirationInstant = (r[expiration] ?: Instant.MIN),
                jwt = try { JWTParser.parse(r[tokenValue]) } catch (e: ParseException) { throw RuntimeException("Failure to parse ${r[tokenValue]}", e) },
                client = client,
                authenticationHolder = authenticationHolder,
                refreshToken = refreshToken,
                scope = scopes,
                tokenType = r[tokenType] ?: OAuth2AccessToken.BEARER_TYPE,
            )
        }

    }

    companion object {
        val logger = getLogger<ExposedOauth2TokenRepository>()
    }
}
