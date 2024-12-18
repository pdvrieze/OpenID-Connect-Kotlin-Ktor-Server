package io.github.pdvrieze.auth.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.lessEq
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.data.PageCriteria
import org.mitre.oauth2.model.AuthorizationCodeEntity
import org.mitre.oauth2.repository.AuthenticationHolderRepository
import org.mitre.oauth2.repository.AuthorizationCodeRepository
import org.mitre.oauth2.repository.ktor.KtorAuthorizationCodeRepository
import org.mitre.oauth2.util.requireId
import java.time.Instant

class ExposedAuthorizationCodeRepository(database: Database, private val authHolders: AuthenticationHolderRepository) :
    RepositoryBase(database, AuthorizationCodes), KtorAuthorizationCodeRepository {

    override fun save(authorizationCode: AuthorizationCodeEntity): AuthorizationCodeEntity {
        val oldId = authorizationCode.id

        return transaction(database) {
            val newId = AuthorizationCodes.save(oldId) { b ->
                b[code] = authorizationCode.code
                authorizationCode.authenticationHolder?.let { ah ->
                    b[authHolderId] = ah.id
                }
                b[expiration] = authorizationCode.expiration?.toInstant()
            }
            authorizationCode.copy(id = newId)
        }
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.AuthorizationCodeRepository#getByCode(java.lang.String)
	 */
    override fun getByCode(code: String): AuthorizationCodeEntity? = transaction(database) {
        AuthorizationCodes.selectAll()
            .where { AuthorizationCodes.code.eq(code) }
            .map { it.toAuthorizationCode() }
            .singleOrNull()
    }

    /* (non-Javadoc)
	 * @see org.mitre.oauth2.repository.AuthorizationCodeRepository#remove(org.mitre.oauth2.model.AuthorizationCodeEntity)
	 */
    override fun remove(authorizationCodeEntity: AuthorizationCodeEntity) {
        transaction(database) {
            AuthorizationCodes.deleteWhere {
                AuthorizationCodes.id eq authorizationCodeEntity.id
            }
        }
    }

    override val expiredCodes: Collection<AuthorizationCodeEntity>
        get() {
            val now = Instant.now()
            return AuthorizationCodes.selectAll()
                .where { AuthorizationCodes.expiration lessEq now }
                .map { it.toAuthorizationCode() }
        }

    override fun clearExpiredCodes() {
        val now = Instant.now()
        transaction(database) {
            AuthorizationCodes.deleteWhere {
                expiration lessEq now
            }
        }

    }

    override fun getExpiredCodes(pageCriteria: PageCriteria): Collection<AuthorizationCodeEntity> {
        val now = Instant.now()
        return transaction(database) { AuthorizationCodes
            .selectAll()
            .where { AuthorizationCodes.expiration lessEq now }
            .limit(pageCriteria.pageSize, (pageCriteria.pageSize.toLong() * pageCriteria.pageNumber.toLong()))
            .map { it.toAuthorizationCode() }
            }
    }

    private fun ResultRow.toAuthorizationCode(): AuthorizationCodeEntity {
        val authHolderId = get(AuthorizationCodes.authHolderId)
        val authHolder = authHolders.getById(authHolderId.requireId())

        return AuthorizationCodeEntity(
            id = get(AuthorizationCodes.id).value,
            code = get(AuthorizationCodes.code),
            authenticationHolder = authHolder,
            expiration = get(AuthorizationCodes.expiration)?.let { java.util.Date.from(it) },
        )
    }
}
