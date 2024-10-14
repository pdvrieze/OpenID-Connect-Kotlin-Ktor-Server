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

import io.ktor.server.routing.*
import org.mitre.util.getLogger
import java.util.*

/**
 * This class sets a timestamp on the current HttpSession
 * when someone successfully authenticates.
 *
 * @author jricher
 */
//@Component("authenticationTimeStamper")
class AuthenticationTimeStamper {
    /**
     * Set the timestamp on the session to mark when the authentication happened,
     * useful for calculating authentication age. This gets stored in the sesion
     * and can get pulled out by other components.
     */
    suspend fun RoutingContext.onAuthenticationSuccess(
//        request: HttpServletRequest,
//        response: HttpServletResponse,
//        authentication: Authentication
    ) {
        val authTimestamp = Date()

//        val session = request.session
//
//        session.setAttribute(AUTH_TIMESTAMP, authTimestamp)
//
//        if (session.getAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED) != null) {
//            session.setAttribute(AuthorizationRequestFilter.PROMPTED, Boolean.TRUE)
//            session.removeAttribute(AuthorizationRequestFilter.PROMPT_REQUESTED)
//        }
//
//        Companion.logger.info("Successful Authentication of ${authentication.name} at $authTimestamp")
//
//        super.onAuthenticationSuccess(request, response, authentication)
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<AuthenticationTimeStamper>()

        const val AUTH_TIMESTAMP: String = "AUTH_TIMESTAMP"
    }
}
