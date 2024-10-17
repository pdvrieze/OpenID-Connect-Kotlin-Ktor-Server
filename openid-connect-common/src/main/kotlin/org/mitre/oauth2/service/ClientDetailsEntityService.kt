package org.mitre.oauth2.service

import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.resolver.ClientResolver

interface ClientDetailsEntityService : ClientResolver {
    fun saveNewClient(client: OAuthClientDetails): OAuthClientDetails =
        saveNewClient(client.builder())

    fun saveNewClient(client: OAuthClientDetails.Builder): OAuthClientDetails

    fun deleteClient(client: OAuthClientDetails)

    fun updateClient(oldClient: OAuthClientDetails, newClient: OAuthClientDetails): OAuthClientDetails

    val allClients: Collection<OAuthClientDetails>

    fun generateClientIdString(client: OAuthClientDetails): String

    fun generateClientSecret(client: OAuthClientDetails.Builder? = null): String?

    fun loadClientAuthenticated(clientId: String, clientPublicSecret: String): ClientLoadingResult

}
