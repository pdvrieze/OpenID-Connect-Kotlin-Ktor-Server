package io.github.pdvrieze.auth.exposed

import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.SqlExpressionBuilder.inList
import org.jetbrains.exposed.sql.SqlExpressionBuilder.inSubQuery
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.batchInsert
import org.jetbrains.exposed.sql.deleteWhere
import org.jetbrains.exposed.sql.selectAll
import org.mitre.uma.model.Claim
import org.mitre.uma.model.Policy
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.ResourceSetRepository

class ExposedResourceSetRepository(database: Database): RepositoryBase(
    database,
    ResourceSets,
    ResourceSetScopes,
    Policies,
    ClaimToPolicies,
    PolicyScopes,
    ClaimTokenFormats,
    ClaimIssuers
), ResourceSetRepository {
    override fun getById(id: Long): ResourceSet? = transaction {
        ResourceSets.selectAll()
            .where { ResourceSets.id eq id }
            .singleOrNull()
            ?.toResourceSet()
    }

    override fun getAllForOwner(owner: String): Collection<ResourceSet> = transaction {
        ResourceSets.selectAll()
            .where { ResourceSets.owner eq owner }
            .map { it.toResourceSet() }
    }

    override fun getAllForOwnerAndClient(owner: String, clientId: String): Collection<ResourceSet> = transaction {
        ResourceSets.selectAll()
            .where { (ResourceSets.owner eq owner) and (ResourceSets.clientId eq clientId) }
            .map { it.toResourceSet() }
    }

    override val all: Collection<ResourceSet>
        get() = ResourceSets.selectAll().map { it.toResourceSet() }

    override fun getAllForClient(clientId: String): Collection<ResourceSet> = transaction {
        ResourceSets.selectAll()
            .where { ResourceSets.clientId eq clientId }
            .map { it.toResourceSet() }
    }

    override fun save(rs: ResourceSet): ResourceSet {
        val oldId = rs.id

        transaction {
            val newId = ResourceSets.save(oldId) { b ->
                b[name] = rs.name
                b[uri] = rs.uri
                b[rsType] = rs.type
                b[iconUri] = rs.iconUri
                rs.owner?.let { b[owner] = it }
                b[clientId] = rs.clientId
            }

            // Get all current scopes
            val currentScopes = when {
                oldId != null -> ResourceSetScopes.select(ResourceSetScopes.scope)
                    .where { ResourceSetScopes.ownerId eq oldId }
                    .mapTo(HashSet()) { it[ResourceSetScopes.scope] }
                else -> emptySet()
            }

            val currentPolicyIds = when {
                oldId != null -> Policies.selectAll().where { Policies.resourceSetId eq oldId }.mapTo(HashSet()) {
                    it[Policies.id].value
                }
                else -> emptySet()
            }


            if(oldId != null) {
                check(oldId == newId) { "Id change is not supported" }
                // Remove all current scopes not in the new list
                currentScopes.filterNot { it in rs.scopes }.let { toDelete ->
                    ResourceSetScopes.deleteWhere { (ownerId eq oldId) and (scope.inList(toDelete)) }
                }

                currentPolicyIds.filterNot { id -> rs.policies.any { it.id == id } }.let { toDelete ->
                    PolicyScopes.deleteWhere { ownerId.inList(toDelete) }
                    ClaimToPolicies.deleteWhere { policyId.inList(toDelete) }

                    Policies.deleteWhere { id.inList(toDelete) }
                }

            }

            if (oldId != null) {
                // Add missing scopes


                rs.scopes.filterNot { it in currentScopes }.let { toAdd ->
                    ResourceSetScopes.batchInsert(toAdd) { scope ->
                        this[ResourceSetScopes.ownerId] = newId
                        this[ResourceSetScopes.scope] = scope
                    }
                }

                ResourceSetScopes.deleteWhere { ownerId eq oldId }

                PolicyScopes.deleteWhere {
                    ownerId.inSubQuery(Policies.select(Policies.id).where { Policies.resourceSetId eq oldId })
                }
                PolicyScopes.deleteWhere {
                    ownerId.inSubQuery(Policies.select(Policies.id).where { Policies.resourceSetId eq oldId })
                }
                Policies.deleteWhere { resourceSetId eq oldId }
            }

            ResourceSetScopes.batchInsert(rs.scopes) { scope ->
                this[ResourceSetScopes.ownerId] = newId
                this[ResourceSetScopes.scope] = scope
            }

            Policies.batchInsert(rs.policies) { policy ->
                this[Policies.name] = policy.name
                this[Policies.resourceSetId] = newId
            }

            rs.id = newId
        }

        return rs
    }

    override fun remove(rs: ResourceSet) {
        val setId = requireNotNull(rs.id)
        transaction {
            ResourceSets.deleteWhere { id eq setId }
        }
    }
}

internal fun ResultRow.toResourceSet(): ResourceSet {
    val r = this
    val setId = r[ResourceSets.id].value

    val scopes = with(ResourceSetScopes) { select(scope).where { ownerId eq setId }.mapTo(HashSet()) { it[scope] } }

    val policies = with(Policies) {
        select(id, name).where { resourceSetId eq setId }
            .map { it.toPolicy() }
    }

    with(ResourceSets) {
        return ResourceSet(
            id = setId,
            name = r[name],
            uri = r[uri],
            type = r[rsType],
            scopes = scopes,
            iconUri = r[iconUri],
            owner = r[owner],
            clientId = r[clientId],
            policies = policies,
        )
    }
}

internal fun ResultRow.toPolicy(): Policy {
    val r = this
    val policyId = this[Policies.id].value

    val claimsRequired: Collection<Claim> = (ClaimToPolicies rightJoin  Claims).select(Claims.columns)
        .where { ClaimToPolicies.policyId.eq(policyId) }
        .map { it.toClaim() }

    val scopes = with(PolicyScopes) {
        select(scope).where { ownerId eq policyId }.mapTo(HashSet()) { it[scope] }
    }

    return Policy(
        id = policyId,
        name = r[Policies.name],
        claimsRequired = claimsRequired,
        scopes = scopes,
    )
}

internal fun ResultRow.toClaim(): Claim {
    val r = this
    val claimId = r[Claims.id].value

    val tokenFormats = with(ClaimTokenFormats) {
        select(claimTokenFormat).where { ownerId eq claimId }.mapTo(HashSet()) { it[claimTokenFormat] }
    }

    val issuers = with(ClaimIssuers) {
        select(issuer).where { ownerId eq claimId }.mapTo(HashSet()) { it[issuer] }
    }

    return with(Claims) {
        Claim(
            id = claimId,
            name = r[name],
            friendlyName = r[friendlyName],
            claimType = r[claimType],
            value = r[claimValue]?.let { Json.parseToJsonElement(it) },
            claimTokenFormat = tokenFormats,
            issuer = issuers,
        )
    }
}
