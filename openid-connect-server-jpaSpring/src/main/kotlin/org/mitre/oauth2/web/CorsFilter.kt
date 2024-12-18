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
package org.mitre.oauth2.web

import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Implements Cross-Origin Resource Sharing (CORS) headers. This filter adds the CORS
 * headers to all requests that pass through it, and as such it should be used only
 * on endpoints that require CORS support.
 *
 * @author jricher
 */
@Component("corsFilter")
class CorsFilter : OncePerRequestFilter() {
    @Throws(IOException::class, ServletException::class)
    public override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        response.addHeader("Access-Control-Allow-Origin", "*")
        if (request.getHeader("Access-Control-Request-Method") != null && "OPTIONS" == request.method) {
            // CORS "pre-flight" request
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
            response.addHeader("Access-Control-Allow-Headers", "X-Requested-With,Origin,Content-Type, Accept, Authorization")
        }
        filterChain.doFilter(request, response)
    }
}
