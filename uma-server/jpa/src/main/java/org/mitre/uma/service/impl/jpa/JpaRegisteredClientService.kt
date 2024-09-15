package org.mitre.uma.service.impl.jpa

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.uma.model.SavedRegisteredClient
import org.mitre.uma.service.SavedRegisteredClientService
import org.mitre.util.jpa.JpaUtil
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

/**
 * @author jricher
 */
@Service
open class JpaRegisteredClientService : RegisteredClientService, SavedRegisteredClientService {
    @PersistenceContext(unitName = "defaultPersistenceUnit")
    private lateinit var em: EntityManager

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#getByIssuer(java.lang.String)
	 */
    override fun getByIssuer(issuer: String): RegisteredClient? {
        val saved = getSavedRegisteredClientFromStorage(issuer)

        return saved?.registeredClient
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.RegisteredClientService#save(java.lang.String, org.mitre.oauth2.model.RegisteredClient)
	 */
    @Transactional(value = "defaultTransactionManager")
    override fun save(issuer: String, client: RegisteredClient) {
        val saved = getSavedRegisteredClientFromStorage(issuer)
            ?: SavedRegisteredClient(issuer = issuer)

        saved.registeredClient = client

        em.persist(saved)
    }

    private fun getSavedRegisteredClientFromStorage(issuer: String): SavedRegisteredClient? {
        val query =
            em.createQuery("SELECT c from SavedRegisteredClient c where c.issuer = :issuer", SavedRegisteredClient::class.java)
        query.setParameter("issuer", issuer)

        return org.mitre.util.jpa.JpaUtil.getSingleResult(query.resultList)
    }


    override val all: Collection<SavedRegisteredClient>
        get() {
            val query = em.createQuery("SELECT c from SavedRegisteredClient c", SavedRegisteredClient::class.java)
            return query.resultList
        }
}
