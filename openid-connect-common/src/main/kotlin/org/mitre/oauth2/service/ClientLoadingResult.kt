package org.mitre.oauth2.service

import org.mitre.oauth2.model.OAuthClientDetails

sealed interface ClientLoadingResult {
    object Missing: ClientLoadingResult {
        override fun get(): OAuthClientDetails? = null
    }

    object Unauthorized: ClientLoadingResult {
        override fun get(): OAuthClientDetails? = null
    }

    class Found(val client: OAuthClientDetails): ClientLoadingResult {
        override fun get(): OAuthClientDetails = client
    }

    fun get(): OAuthClientDetails?
}
