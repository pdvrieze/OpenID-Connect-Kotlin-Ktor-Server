package org.mitre.oauth2.service

import org.mitre.oauth2.exception.InvalidRequestException.Companion.INVALID_REQUEST_CODE
import org.mitre.oauth2.exception.OpenConnectException
import org.mitre.oauth2.model.OAuthClientDetails

interface RedirectResolver {
    fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String
    fun redirectMatches(requestedRedirect: String, redirectUri: String): Boolean

    class RedirectMismatchException: OpenConnectException {
        constructor(message: String?) : super(INVALID_REQUEST_CODE, message)
    }
}
