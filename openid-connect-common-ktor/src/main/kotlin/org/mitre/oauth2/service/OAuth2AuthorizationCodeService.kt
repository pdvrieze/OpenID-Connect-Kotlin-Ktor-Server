package org.mitre.oauth2.service

import org.mitre.oauth2.model.AuthenticatedAuthorizationRequest
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.SavedUserAuthentication
import org.mitre.oauth2.model.request.AuthorizationRequest

interface OAuth2AuthorizationCodeService {
    /**
     * Generate a random authorization code and create an AuthorizationCodeEntity,
     * which will be stored in the repository.
     *
     * @param authentication    the authentication of the current user, to be retrieved when the
     * code is consumed
     * @return                    the authorization code
     */
    fun createAuthorizationCode(authentication: AuthenticatedAuthorizationRequest): String

    fun createAuthorizationCode(request: AuthorizationRequest, auth: Authentication): String {
        val authentication = AuthenticatedAuthorizationRequest(request, SavedUserAuthentication.from(auth))
        return createAuthorizationCode(authentication)
    }

    /**
     * Consume a given authorization code.
     * Match the provided string to an AuthorizationCodeEntity. If one is found, return
     * the authentication associated with the code. If one is not found, throw an
     * InvalidGrantException.
     *
     * @param code        the authorization code
     * @return            the authentication that made the original request
     * @throws            InvalidGrantException, if an AuthorizationCodeEntity is not found with the given value
     */
    fun consumeAuthorizationCode(code: String): AuthenticatedAuthorizationRequest

    /**
     * Find and remove all expired auth codes.
     */
    fun clearExpiredAuthorizationCodes()

}
