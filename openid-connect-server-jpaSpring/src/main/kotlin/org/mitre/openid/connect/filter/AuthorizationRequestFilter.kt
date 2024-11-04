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
package org.mitre.openid.connect.filter

import org.apache.http.client.utils.URIBuilder
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.oauth2.service.ClientDetailsEntityService
import org.mitre.openid.connect.request.ConnectRequestParameters
import org.mitre.openid.connect.request.Prompt
import org.mitre.openid.connect.service.LoginHintExtracter
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP
import org.mitre.openid.connect.web.AuthenticationTimeStamper
import org.mitre.util.getLogger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.common.exceptions.InvalidClientException
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.ClientDetails
import org.springframework.security.oauth2.provider.OAuth2RequestFactory
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.stereotype.Component
import org.springframework.web.filter.GenericFilterBean
import java.io.IOException
import java.net.URISyntaxException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * @author jricher
 */
@Component("authRequestFilter")
class AuthorizationRequestFilter : GenericFilterBean() {
    @Autowired
    private lateinit var authRequestFactory: OAuth2RequestFactory

    @Autowired
    private lateinit var clientService: ClientDetailsEntityService

    @Autowired
    private lateinit var redirectResolver: RedirectResolver

    @Autowired(required = false)
    private val loginHintExtracter: LoginHintExtracter = RemoveLoginHintsWithHTTP()

    var requestMatcher: RequestMatcher = AntPathRequestMatcher("/authorize")


    @Throws(IOException::class, ServletException::class)
    override fun doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain) {
        val request = req as HttpServletRequest
        val response = res as HttpServletResponse
        val session = request.session

        // skip everything that's not an authorize URL
        if (!requestMatcher.matches(request)) {
            chain.doFilter(req, res)
            return
        }

        try {
            // we have to create our own auth request in order to get at all the parmeters appropriately
            val authRequest: AuthorizationRequest?

            var client: OAuthClientDetails? = null

            authRequest = authRequestFactory
                .createAuthorizationRequest(createRequestMap(request.parameterMap as Map<String, Array<String>?>))

            if (!authRequest.clientId.isNullOrEmpty()) {
                client = clientService.loadClientByClientId(authRequest.clientId)
            }

            // save the login hint to the session
            // but first check to see if the login hint makes any sense
            val loginHint =
                loginHintExtracter.extractHint(authRequest.extensions[ConnectRequestParameters.LOGIN_HINT] as String?)
            if (!loginHint.isNullOrEmpty()) {
                session.setAttribute(ConnectRequestParameters.LOGIN_HINT, loginHint)
            } else {
                session.removeAttribute(ConnectRequestParameters.LOGIN_HINT)
            }

            val extPrompt = authRequest.extensions[ConnectRequestParameters.PROMPT] as? String
            if (extPrompt != null) {
                // we have a "prompt" parameter
                val prompt = extPrompt
                val prompts = Prompt.parseSet(prompt)

                if (Prompt.NONE in prompts) {
                    // see if the user's logged in
                    val auth = SecurityContextHolder.getContext().authentication

                    if (auth != null) {
                        // user's been logged in already (by session management)
                        // we're OK, continue without prompting
                        chain.doFilter(req, res)
                    } else {
                        Companion.logger.info("Client requested no prompt")
                        // user hasn't been logged in, we need to "return an error"
                        if (client != null && authRequest.redirectUri != null) {
                            // if we've got a redirect URI then we'll send it

                            // TODO Stuck to spring/ClientDetails
                            val url = redirectResolver.resolveRedirect(authRequest.redirectUri, client as ClientDetails)

                            try {
                                val uriBuilder = URIBuilder(url)

                                uriBuilder.addParameter(ConnectRequestParameters.ERROR, ConnectRequestParameters.LOGIN_REQUIRED)
                                if (!authRequest.state.isNullOrEmpty()) {
                                    uriBuilder.addParameter(ConnectRequestParameters.STATE, authRequest.state) // copy the state parameter if one was given
                                }

                                response.sendRedirect(uriBuilder.toString())
                                return
                            } catch (e: URISyntaxException) {
                                Companion.logger.error("Can't build redirect URI for prompt=none, sending error instead", e)
                                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")
                                return
                            }
                        }

                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied")
                        return
                    }
                } else if (prompts.contains(Prompt.LOGIN)) {
                    // first see if the user's already been prompted in this session

                    if (session.getAttribute(PROMPTED) == null) {
                        // user hasn't been PROMPTED yet, we need to check

                        session.setAttribute(PROMPT_REQUESTED, true)

                        // see if the user's logged in
                        val auth = SecurityContextHolder.getContext().authentication
                        if (auth != null) {
                            // user's been logged in already (by session management)
                            // log them out and continue
                            SecurityContextHolder.getContext().authentication = null
                            chain.doFilter(req, res)
                        } else {
                            // user hasn't been logged in yet, we can keep going since we'll get there
                            chain.doFilter(req, res)
                        }
                    } else {
                        // user has been PROMPTED, we're fine

                        // but first, undo the prompt tag

                        session.removeAttribute(PROMPTED)
                        chain.doFilter(req, res)
                    }
                } else {
                    // prompt parameter is a value we don't care about, not our business
                    chain.doFilter(req, res)
                }
            } else if (authRequest.extensions[ConnectRequestParameters.MAX_AGE] != null ||
                (client?.defaultMaxAge != null)
            ) {
                // default to the client's stored value, check the string parameter

                var max = (client?.defaultMaxAge)
                val maxAge = authRequest.extensions[ConnectRequestParameters.MAX_AGE] as String?
                if (maxAge != null) {
                    max = maxAge.toLong()
                }

                if (max != null) {
                    val authTime = session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP) as Date?

                    val now = Date()
                    if (authTime != null) {
                        val seconds = (now.time - authTime.time) / 1000
                        if (seconds > max) {
                            // session is too old, log the user out and continue
                            SecurityContextHolder.getContext().authentication = null
                        }
                    }
                }
                chain.doFilter(req, res)
            } else {
                // no prompt parameter, not our business
                chain.doFilter(req, res)
            }
        } catch (e: InvalidClientException) {
            // we couldn't find the client, move on and let the rest of the system catch the error
            chain.doFilter(req, res)
        }
    }


    private fun createRequestMap(parameterMap: Map<String, Array<String>?>): Map<String, String> {
        val requestMap: MutableMap<String, String> = HashMap()
        for ((key, value) in parameterMap) {
            if (!value.isNullOrEmpty()) {
                requestMap[key] = value[0] // add the first value only (which is what Spring seems to do)
            }
        }

        return requestMap
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<AuthorizationRequestFilter>()

        const val PROMPTED: String = "PROMPT_FILTER_PROMPTED"
        const val PROMPT_REQUESTED: String = "PROMPT_FILTER_REQUESTED"
    }
}
