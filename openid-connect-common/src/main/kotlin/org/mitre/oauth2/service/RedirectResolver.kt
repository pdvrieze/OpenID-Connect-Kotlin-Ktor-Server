package org.mitre.oauth2.service

import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.model.OAuthClientDetails

interface RedirectResolver {
    fun resolveRedirect(requestedRedirect: String, client: OAuthClientDetails): String
    fun redirectMatches(requestedRedirect: String, redirectUri: String): Boolean

    class RedirectMismatchException: AuthenticationException {
        constructor(message: String?) : super(message)
    }
}
