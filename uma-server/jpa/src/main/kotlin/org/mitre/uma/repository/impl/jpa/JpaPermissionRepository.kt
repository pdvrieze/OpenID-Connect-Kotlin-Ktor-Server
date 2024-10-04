package org.mitre.uma.repository.impl.jpa

import org.mitre.uma.model.Permission
import org.mitre.uma.model.PermissionTicket
import org.mitre.uma.model.ResourceSet
import org.mitre.uma.repository.PermissionRepository
import org.mitre.util.jpa.JpaUtil
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Repository
open class JpaPermissionRepository : PermissionRepository {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    @Transactional(value = "defaultTransactionManager")
    override fun save(p: PermissionTicket): PermissionTicket? {
        return JpaUtil.saveOrUpdate<PermissionTicket?, Long?>(p.id, em, p)
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#getByTicket(java.lang.String)
	 */
    override fun getByTicket(ticket: String): PermissionTicket? {
        val query = em.createNamedQuery(PermissionTicket.QUERY_TICKET, PermissionTicket::class.java)
        query.setParameter(PermissionTicket.PARAM_TICKET, ticket)
        return JpaUtil.getSingleResult(query.resultList)
    }

        /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#getAll()
	 */
    override val all: Collection<PermissionTicket>?
            get() {
            val query = em.createNamedQuery(PermissionTicket.QUERY_ALL, PermissionTicket::class.java)
            return query.resultList
        }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#saveRawPermission(org.mitre.uma.model.Permission)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun saveRawPermission(p: Permission): Permission {
        return JpaUtil.saveOrUpdate(p.id, em, p)
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#getById(java.lang.Long)
	 */
    override fun getById(permissionId: Long): Permission? {
        return em.find(Permission::class.java, permissionId)
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#getPermissionTicketsForResourceSet(org.mitre.uma.model.ResourceSet)
	 */
    override fun getPermissionTicketsForResourceSet(rs: ResourceSet): Collection<PermissionTicket>? {
        val query = em.createNamedQuery(PermissionTicket.QUERY_BY_RESOURCE_SET, PermissionTicket::class.java)
        query.setParameter(PermissionTicket.PARAM_RESOURCE_SET_ID, rs.id)
        return query.resultList
    }

    /* (non-Javadoc)
	 * @see org.mitre.uma.repository.PermissionRepository#remove(org.mitre.uma.model.PermissionTicket)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun remove(ticket: PermissionTicket) {
        val found = getByTicket(ticket.ticket?: return)
        if (found != null) {
            em.remove(found)
        }
    }
}
