package org.mitre.oauth2.repository

import org.mitre.oauth2.model.OAuthClientDetails

interface OAuth2ClientRepository {
    fun getById(id: Long): OAuthClientDetails?

    fun getClientByClientId(clientId: String): OAuthClientDetails?

    fun saveClient(client: OAuthClientDetails): OAuthClientDetails

    fun deleteClient(client: OAuthClientDetails)

    fun updateClient(id: Long, client: OAuthClientDetails): OAuthClientDetails

    val allClients: Collection<OAuthClientDetails>
}
