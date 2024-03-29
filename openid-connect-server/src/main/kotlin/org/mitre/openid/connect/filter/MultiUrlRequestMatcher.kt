/*******************************************************************************
 * Copyright 2018 The MIT Internet Trust Consortium
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

import org.springframework.security.web.util.UrlUtils
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.http.HttpServletRequest

/**
 * @author jricher
 */
class MultiUrlRequestMatcher(filterProcessesUrls: Set<String>) : RequestMatcher {
    private val matchers: MutableSet<RequestMatcher> =
        HashSet(filterProcessesUrls.size)

    init {
        for (filterProcessesUrl in filterProcessesUrls) {
            require(filterProcessesUrl.isNotEmpty()) { "filterProcessesUrl must be specified" }
            require(UrlUtils.isValidRedirectUrl(filterProcessesUrl)) { "$filterProcessesUrl isn't a valid URL" }
            matchers.add(AntPathRequestMatcher(filterProcessesUrl))
        }
    }

    override fun matches(request: HttpServletRequest): Boolean {
        return matchers.any { it.matches(request) }
    }
}
