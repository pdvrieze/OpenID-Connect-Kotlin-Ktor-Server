package org.mitre.uma.service.impl.ktor

import io.github.pdvrieze.auth.exposed.RepositoryBase
import io.github.pdvrieze.auth.uma.repository.exposed.SavedRegisteredClients
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.selectAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.mitre.oauth2.model.RegisteredClient
import org.mitre.openid.connect.client.service.RegisteredClientService
import org.mitre.uma.model.SavedRegisteredClient
import org.mitre.uma.service.SavedRegisteredClientService

/**
 * @author jricher
 */
open class KtorRegisteredClientService(database: Database) :
    RepositoryBase(database, SavedRegisteredClients), RegisteredClientService, SavedRegisteredClientService {

        val json = Json

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
    override fun save(issuer: String, client: RegisteredClient) {
        val saved = getSavedRegisteredClientFromStorage(issuer)

        val oldId = saved?.id

        transaction(database) {
            val newId = SavedRegisteredClients.save(oldId) { b ->
                b[this.issuer] = issuer
                b[registeredClient] = json.encodeToString(client)
            }
        }
    }

    private fun getSavedRegisteredClientFromStorage(issuer: String): SavedRegisteredClient? {
        return transaction(db = database) {
            SavedRegisteredClients.selectAll().where { SavedRegisteredClients.issuer eq issuer }
                .map { rr -> rr.toSavedRegisteredClient() }
                .singleOrNull()
        }
    }


    override val all: Collection<SavedRegisteredClient>
        get() {
            return transaction(database) {
                SavedRegisteredClients.selectAll().map { rr -> rr.toSavedRegisteredClient() }
            }
        }

    private fun ResultRow.toSavedRegisteredClient(): SavedRegisteredClient {
        return SavedRegisteredClient(
            id = get(SavedRegisteredClients.id).value,
            issuer = get(SavedRegisteredClients.issuer),
            registeredClient = json.decodeFromString<RegisteredClient>(get(SavedRegisteredClients.registeredClient))
        )
    }
}
