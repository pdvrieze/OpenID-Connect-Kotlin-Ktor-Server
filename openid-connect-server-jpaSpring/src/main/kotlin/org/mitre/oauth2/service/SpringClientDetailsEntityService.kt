package org.mitre.oauth2.service

import org.mitre.oauth2.model.ClientDetailsEntity

interface SpringClientDetailsEntityService : ClientDetailsEntityService {

    override fun loadClientByClientId(clientId: String): ClientDetailsEntity?

}
