package io.github.pdvrieze.auth.repository.exposed

import io.github.pdvrieze.auth.exposed.RepositoryBase
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.inList
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.oauth2.model.DeviceCode
import org.mitre.oauth2.repository.DeviceCodeRepository
import java.time.Instant
import java.util.*

class ExposedDeviceCodeRepository(
    dataSource: Database,
    private val clientDetails: ExposedOauth2ClientRepository,
    private val authenticationHolders: ExposedAuthenticationHolderRepository,
) : RepositoryBase(dataSource, DeviceCodes, DeviceCodeScopes, DeviceCodeRequestParameters),
    DeviceCodeRepository {
    override fun getById(id: Long): DeviceCode? {
        return DeviceCodes.selectAll()
            .where { DeviceCodes.id eq id }
            .map { it.toDeviceCode() }
            .singleOrNull()
    }

    override fun getByUserCode(value: String): DeviceCode? {
        return DeviceCodes.selectAll()
            .where { DeviceCodes.userCode eq value }
            .map { it.toDeviceCode() }
            .singleOrNull()
    }

    /* (non-Javadoc)
     */
    override fun getByDeviceCode(value: String): DeviceCode? {
        return DeviceCodes.selectAll()
            .where { DeviceCodes.deviceCode eq value }
            .map { it.toDeviceCode() }
            .singleOrNull()
    }

    /* (non-Javadoc)
     */
    override fun remove(code: DeviceCode) {
        val scopeId = code.id ?: return
        transaction {
            DeviceCodeRequestParameters.deleteWhere { DeviceCodeRequestParameters.ownerId eq scopeId }
            DeviceCodeScopes.deleteWhere { DeviceCodeScopes.ownerId eq scopeId }
            DeviceCodes.deleteWhere { id eq scopeId }
        }
    }

    /* (non-Javadoc)
     * @see org.mitre.oauth2.repository.SystemScopeRepository#save(org.mitre.oauth2.model.SystemScope)
     */
    override fun save(code: DeviceCode): DeviceCode? {
        val oldId = code.id
        var newId: Long
        transaction {
            newId = DeviceCodes.save(oldId) { b ->
                b[DeviceCodes.deviceCode] = code.deviceCode
                b[DeviceCodes.userCode] = code.userCode
                b[DeviceCodes.expiration] = code.expiration?.toInstant()
                b[DeviceCodes.clientId] = code.clientId
                b[DeviceCodes.approved] = code.isApproved
                b[DeviceCodes.authHolderId] = code.authenticationHolder?.id
            }

            val scopesToAdd: Set<String>
            if (oldId == newId) {
                val oldScopes = DeviceCodeScopes.selectAll().where { DeviceCodeScopes.ownerId eq oldId }.map { it[DeviceCodeScopes.scope] }
                val scopesToRemove: Set<String>
                scopesToRemove = oldScopes.toMutableSet().apply {
                    code.scope?.let { removeAll(it)}
                }
                scopesToAdd = code.scope?.run { toMutableSet().apply { removeAll(oldScopes) } } ?: emptySet()
                DeviceCodeScopes.deleteWhere { (DeviceCodeScopes.ownerId eq oldId) and (DeviceCodeScopes.scope inList scopesToRemove) }
                DeviceCodeRequestParameters.deleteWhere { DeviceCodeRequestParameters.ownerId eq oldId }
            } else {
                if (oldId != null) {
                    DeviceCodeScopes.deleteWhere { DeviceCodeScopes.ownerId eq oldId }
                    DeviceCodeRequestParameters.deleteWhere { DeviceCodeRequestParameters.ownerId eq oldId }
                }
                scopesToAdd = code.scope ?: emptySet()
            }

            if (oldId != null) {
                DeviceCodeScopes.deleteWhere { DeviceCodeScopes.ownerId eq oldId }
                DeviceCodeRequestParameters.deleteWhere { DeviceCodeRequestParameters.ownerId eq oldId }
            }
            if (scopesToAdd.isNotEmpty()) {
                DeviceCodeScopes.batchInsert(scopesToAdd) { elem ->
                    this[DeviceCodeScopes.ownerId] = newId
                    this[DeviceCodeScopes.scope] = elem
                }

            }

            code.requestParameters?.let { p ->
                DeviceCodeRequestParameters.batchInsert(p.entries) { (k, v) ->
                    this[DeviceCodeRequestParameters.ownerId] = newId
                    this[DeviceCodeRequestParameters.param] = k
                    this[DeviceCodeRequestParameters.value] = v
                }
            }

        }

        return code.copy(id = newId)
    }

    override val expiredCodes: Collection<DeviceCode>
        get() {
            val now = Instant.now()
            return AuthorizationCodes.selectAll()
                .where { AuthorizationCodes.expiration lessEq now }
                .map { it.toDeviceCode() }
        }

    fun ResultRow.toDeviceCode(): DeviceCode {
        val id = get(DeviceCodes.id).value
        val scopes = DeviceCodeScopes
            .selectAll()
            .where { DeviceCodeScopes.ownerId eq id }
            .mapTo(HashSet()) { it[DeviceCodeScopes.scope] }

        val params = DeviceCodeRequestParameters
            .selectAll()
            .where { DeviceCodeRequestParameters.ownerId eq id }
            .associate { it[DeviceCodeRequestParameters.param] to it[DeviceCodeRequestParameters.value] }

        val authHolder = authenticationHolders.getById(get(DeviceCodes.authHolderId)!!)

        return DeviceCode(
            id = get(DeviceCodes.id).value,
            deviceCode = get(DeviceCodes.deviceCode),
            userCode = get(DeviceCodes.userCode),
            expiration = get(DeviceCodes.expiration)?.let { Date.from(it) },
            scope = scopes,
            clientId = get(DeviceCodes.clientId),
            approved = get(DeviceCodes.approved),
            authenticationHolder = authHolder,
            params = params,
        )
    }

}
