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
package org.mitre.openid.connect.web

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.nullable
import org.mitre.oauth2.model.convert.SimpleGrantedAuthorityStringConverter
import org.mitre.openid.connect.model.OIDCAuthenticationToken
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.openid.connect.service.UserInfoService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.servlet.AsyncHandlerInterceptor
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Injects the UserInfo object for the current user into the current model's context, if both exist. Allows JSPs and the like to call "userInfo.name" and other fields.
 *
 * @author jricher
 */
@Component
class UserInfoInterceptor : AsyncHandlerInterceptor {
    @Autowired(required = false)
    private val userInfoService: UserInfoService? = null

    private val trustResolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()

    @Throws(Exception::class)
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        val auth = SecurityContextHolder.getContext().authentication

        if (auth is Authentication) {
            val a = MITREidDataService.json.encodeToString(ListSerializer(SimpleGrantedAuthorityStringConverter()).nullable, auth.authorities?.map { SimpleGrantedAuthority(it.authority) })
            request.setAttribute("userAuthorities", a)
        }

        if (!trustResolver.isAnonymous(auth)) { // skip lookup on anonymous logins
            if (auth is OIDCAuthenticationToken) {
                // if they're logging into this server from a remote OIDC server, pass through their user info
                val oidc = auth
                if (oidc.userInfo != null) {
                    request.setAttribute("userInfo", oidc.userInfo)
                    request.setAttribute("userInfoJson", oidc.userInfo.toJson())
                } else {
                    request.setAttribute("userInfo", null)
                    request.setAttribute("userInfoJson", "null")
                }
            } else {
                // don't bother checking if we don't have a principal or a userInfoService to work with
                if (auth != null && auth.name != null) {
                    // try to look up a user based on the principal's name

                    val user = userInfoService?.getByUsername(auth.name)

                    // if we have one, inject it so views can use it
                    if (user != null) {
                        request.setAttribute("userInfo", user)
                        request.setAttribute("userInfoJson", user.toJson())
                    }
                }
            }
        }

        return true
    }
}
