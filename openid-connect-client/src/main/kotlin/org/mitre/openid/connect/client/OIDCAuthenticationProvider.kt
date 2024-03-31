/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
 *
 * Portions copyright 2011-2013 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.openid.connect.client

import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.mitre.openid.connect.model.UserInfo
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException

/**
 * @author nemonik, Justin Richer
 */
class OIDCAuthenticationProvider : AuthenticationProvider {
    private var userInfoFetcher = UserInfoFetcher()

    private var authoritiesMapper: OIDCAuthoritiesMapper = NamedAdminAuthoritiesMapper()

    /*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.authentication.AuthenticationProvider#
	 * authenticate(org.springframework.security.core.Authentication)
	 */
    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication? {
        if (!supports(authentication.javaClass)) {
            return null
        }

        if (authentication is PendingOIDCAuthenticationToken) {
            val token = authentication

            // get the ID Token value out
            val idToken = token.idToken

            // load the user info if we can
            val userInfo = userInfoFetcher.loadUserInfo(token)

            if (userInfo == null) {
                // user info not found -- could be an error, could be fine
            } else {
                // if we found userinfo, double check it
                if (!userInfo.sub.isNullOrEmpty() && userInfo.sub != token.sub) {
                    // the userinfo came back and the user_id fields don't match what was in the id_token
                    throw UsernameNotFoundException("user_id mismatch between id_token and user_info call: " + token.sub + " / " + userInfo.sub)
                }
            }

            return createAuthenticationToken(token, authoritiesMapper.mapAuthorities(idToken!!, userInfo), userInfo)
        }

        return null
    }

    /**
     * Override this function to return a different kind of Authentication, processes the authorities differently,
     * or do post-processing based on the UserInfo object.
     *
     */
    protected fun createAuthenticationToken(
        token: PendingOIDCAuthenticationToken,
        authorities: Collection<GrantedAuthority>?,
        userInfo: UserInfo?
    ): Authentication {
        return OIDCAuthenticationToken(
            token.sub,
            token.issuer,
            userInfo, authorities,
            token.idToken, token.accessTokenValue, token.refreshTokenValue
        )
    }


    fun setUserInfoFetcher(userInfoFetcher: UserInfoFetcher) {
        this.userInfoFetcher = userInfoFetcher
    }


    fun setAuthoritiesMapper(authoritiesMapper: OIDCAuthoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper
    }

    /*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.authentication.AuthenticationProvider#supports
	 * (java.lang.Class)
	 */
    override fun supports(authentication: Class<*>?): Boolean {
        return PendingOIDCAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(OIDCAuthenticationProvider::class.java)
    }
}
