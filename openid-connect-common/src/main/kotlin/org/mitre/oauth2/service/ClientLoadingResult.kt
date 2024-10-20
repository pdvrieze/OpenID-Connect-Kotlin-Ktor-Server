package org.mitre.oauth2.service

import org.mitre.oauth2.exception.OAuthErrorCode
import org.mitre.oauth2.model.OAuthClientDetails

sealed interface ClientLoadingResult {
    object Missing: ClientLoadingResult {
        override fun get(): Nothing? = null
    }

    class Error(val errorCode: OAuthErrorCode, val status: Int? = errorCode.rawHttpCode): ClientLoadingResult {
        override fun get(): Nothing? = null
    }

    object Unauthorized: ClientLoadingResult {
        override fun get(): Nothing? = null
    }

    class Found(val client: OAuthClientDetails): ClientLoadingResult {
        override fun get(): OAuthClientDetails = client
    }

    fun get(): OAuthClientDetails?

    companion object {
        operator fun invoke(errorCode: OAuthErrorCode, status: Int? = null): Error =
            Error(errorCode, status)

        operator fun invoke(client: OAuthClientDetails): Found =
            Found(client)
    }
}
