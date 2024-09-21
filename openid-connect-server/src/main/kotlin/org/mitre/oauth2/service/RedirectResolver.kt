package org.mitre.oauth2.service

import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.OpenConnectException
import org.mitre.oauth2.model.OAuthClientDetails

interface RedirectResolver {
    fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String
    fun redirectMatches(requestedRedirect: String, redirectUri: String): Boolean

    class RedirectMismatchException: OpenConnectException {
        constructor(message: String?) : super(OAuthErrorCodes.INVALID_REQUEST, message)
    }
}
