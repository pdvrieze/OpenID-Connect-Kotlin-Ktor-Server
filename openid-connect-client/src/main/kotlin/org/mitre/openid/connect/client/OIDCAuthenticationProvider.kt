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

import io.github.pdvrieze.openid.spring.SpringFacade
import io.github.pdvrieze.openid.spring.toSpring
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken
import org.mitre.openid.connect.model.UserInfo
import org.mitre.util.getLogger
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.core.GrantedAuthority as SpringGrantedAuthority

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

        val token = (authentication as? SpringFacade<*> ?: return null).original

        if (!supports(token.javaClass)) {
            return null
        }

        if (token !is PendingOIDCAuthenticationToken) return null

        // get the ID Token value out
        val idToken = token.idToken

        // load the user info if we can
        val userInfo = userInfoFetcher.loadUserInfo(token)

        if (userInfo == null) {
            // user info not found -- could be an error, could be fine
        } else {
            // if we found userinfo, double check it
            if (!userInfo.subject.isNullOrEmpty() && userInfo.subject != token.sub) {
                // the userinfo came back and the user_id fields don't match what was in the id_token
                throw UsernameNotFoundException("user_id mismatch between id_token and user_info call: " + token.sub + " / " + userInfo.subject)
            }
        }

        return createAuthenticationToken(token, authoritiesMapper.mapAuthorities(idToken!!, userInfo), userInfo)

        return null
    }

    /**
     * Override this function to return a different kind of Authentication, processes the authorities differently,
     * or do post-processing based on the UserInfo object.
     *
     */
    protected fun createAuthenticationToken(
        token: PendingOIDCAuthenticationToken,
        authorities: Collection<SpringGrantedAuthority>?,
        userInfo: UserInfo?
    ): Authentication {
        return OIDCAuthenticationToken(
            token.sub,
            token.issuer,
            userInfo, authorities?.map { GrantedAuthority(it.authority) },
            token.idToken, token.accessTokenValue, token.refreshTokenValue
        ).toSpring()
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
        return SpringFacade::class.java.isAssignableFrom(authentication)
    }

    companion object {
        private val logger = getLogger<OIDCAuthenticationProvider>()
    }
}
