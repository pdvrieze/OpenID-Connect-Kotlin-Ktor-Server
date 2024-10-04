package org.mitre.oauth2.resolver

import org.mitre.oauth2.model.OAuthClientDetails

interface ClientResolver {
    fun getClientById(id: Long): OAuthClientDetails?
    fun loadClientByClientId(clientId: String): OAuthClientDetails?

}
