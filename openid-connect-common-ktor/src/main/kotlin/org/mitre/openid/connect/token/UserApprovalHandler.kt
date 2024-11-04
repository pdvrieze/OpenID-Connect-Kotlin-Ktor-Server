package org.mitre.openid.connect.token

import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.convert.AuthorizationRequest

interface UserApprovalHandler {
    /**
     * Check if the user has already stored a positive approval decision for this site; or if the
     * site is whitelisted, approve it automatically.
     *
     * Otherwise, return false so that the user will see the approval page and can make their own decision.
     *
     * @param authorizationRequest    the incoming authorization request
     * @param userAuthentication    the Principal representing the currently-logged-in user
     *
     * @return                        true if the site is approved, false otherwise
     */
    fun isApproved(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        postParams: Map<String, String>
    ): Boolean

    /**
     * Check if the user has already stored a positive approval decision for this site; or if the
     * site is whitelisted, approve it automatically.
     *
     * Otherwise the user will be directed to the approval page and can make their own decision.
     *
     * @param authorizationRequest    the incoming authorization request
     * @param userAuthentication    the Principal representing the currently-logged-in user
     *
     * @return                        the updated AuthorizationRequest
     */
    fun checkForPreApproval(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        prompts: Set<Any>?
    ): AuthorizationRequest

    fun updateAfterApproval(
        authorizationRequest: AuthorizationRequest,
        userAuthentication: Authentication,
        postParams: Map<String, String>
    ): AuthorizationRequest

}
