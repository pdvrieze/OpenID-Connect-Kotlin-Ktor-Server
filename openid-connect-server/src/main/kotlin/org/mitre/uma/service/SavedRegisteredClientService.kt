package org.mitre.uma.service

import org.mitre.oauth2.model.RegisteredClient
import org.mitre.uma.model.SavedRegisteredClient

/**
 * @author jricher
 */
interface SavedRegisteredClientService {
    /**
     * Get a list of all the registered clients that we know about.
     */
    val all: Collection<SavedRegisteredClient>


    fun save(issuer: String, client: RegisteredClient)
}
