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
