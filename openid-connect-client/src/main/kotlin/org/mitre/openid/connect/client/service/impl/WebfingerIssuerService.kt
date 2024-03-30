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
package org.mitre.openid.connect.client.service.impl

import com.google.common.base.Strings
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.google.common.cache.LoadingCache
import com.google.common.util.concurrent.UncheckedExecutionException
import com.google.gson.JsonParseException
import com.google.gson.JsonParser
import org.apache.http.client.HttpClient
import org.apache.http.client.utils.URIBuilder
import org.apache.http.impl.client.HttpClientBuilder
import org.mitre.discovery.util.WebfingerURLNormalizer.normalizeResource
import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import java.util.concurrent.ExecutionException
import javax.servlet.http.HttpServletRequest

/**
 * Use Webfinger to discover the appropriate issuer for a user-given input string.
 * @author jricher
 */
class WebfingerIssuerService(
    httpClient: HttpClient?
) : IssuerService {
    constructor() : this(HttpClientBuilder.create().useSystemProperties().build())

    // map of user input -> issuer, loaded dynamically from webfinger discover
    private val issuers: LoadingCache<String, LoadingResult>

    // private data shuttle class to get back two bits of info from the cache loader
    private inner class LoadingResult(var loginHint: String?, var issuer: String)

    var whitelist: Set<String> = HashSet()
    var blacklist: Set<String> = HashSet()

    /**
     * Name of the incoming parameter to check for discovery purposes.
     */
    var parameterName: String = "identifier"

    /**
     * URL of the page to forward to if no identifier is given.
     */
    var loginPageUrl: String? = null

    /**
     * Strict enfocement of "https"
     */
    var isForceHttps: Boolean = true

    init {
        issuers = CacheBuilder.newBuilder().build(WebfingerIssuerFetcher(httpClient))
    }

    /* (non-Javadoc)
	 * @see org.mitre.openid.connect.client.service.IssuerService#getIssuer(javax.servlet.http.HttpServletRequest)
	 */
    override fun getIssuer(request: HttpServletRequest): IssuerServiceResponse? {
        val identifier = request.getParameter(parameterName)
        if (!Strings.isNullOrEmpty(identifier)) {
            try {
                val lr = issuers[identifier]
                if (!whitelist.isEmpty() && !whitelist.contains(lr.issuer)) {
                    throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: " + lr.issuer)
                }

                if (blacklist.contains(lr.issuer)) {
                    throw AuthenticationServiceException("Issuer was in blacklist: " + lr.issuer)
                }

                return IssuerServiceResponse(lr.issuer, lr.loginHint, request.getParameter("target_link_uri"))
            } catch (e: UncheckedExecutionException) {
                logger.warn("Issue fetching issuer for user input: " + identifier + ": " + e.message)
                return null
            } catch (e: ExecutionException) {
                logger.warn("Issue fetching issuer for user input: " + identifier + ": " + e.message)
                return null
            }
        } else {
            logger.warn("No user input given, directing to login page: $loginPageUrl")
            return IssuerServiceResponse(loginPageUrl)
        }
    }


    /**
     * @author jricher
     */
    private inner class WebfingerIssuerFetcher(httpClient: HttpClient?) : CacheLoader<String, LoadingResult>() {
        private val httpFactory = HttpComponentsClientHttpRequestFactory(httpClient)
        private val parser = JsonParser()

        @Throws(Exception::class)
        override fun load(identifier: String): LoadingResult {
            val key = normalizeResource(identifier)

            val restTemplate = RestTemplate(httpFactory)

            // construct the URL to go to
            var scheme = key!!.scheme

            // preserving http scheme is strictly for demo system use only.
            if (!Strings.isNullOrEmpty(scheme) && scheme == "http") {
                // add on colon and slashes.
                require(!isForceHttps) { "Scheme must not be 'http'" }
                logger.warn("Webfinger endpoint MUST use the https URI scheme, overriding by configuration")
                scheme = "http://" // add on colon and slashes.
            } else {
                // otherwise we don't know the scheme, assume HTTPS
                scheme = "https://"
            }

            // do a webfinger lookup
            val builder = URIBuilder(
                scheme
                        + key.host
                        + (if (key.port >= 0) ":" + key.port else "")
                        + Strings.nullToEmpty(key.path)
                        + "/.well-known/webfinger"
                        + (if (Strings.isNullOrEmpty(key.query)) "" else "?" + key.query)
            )
            builder.addParameter("resource", identifier)
            builder.addParameter("rel", "http://openid.net/specs/connect/1.0/issuer")

            try {
                // do the fetch

                logger.info("Loading: $builder")
                val webfingerResponse = restTemplate.getForObject(builder.build(), String::class.java)

                val json = parser.parse(webfingerResponse)

                if (json != null && json.isJsonObject) {
                    // find the issuer
                    val links = json.asJsonObject["links"].asJsonArray
                    for (link in links) {
                        if (link.isJsonObject) {
                            val linkObj = link.asJsonObject
                            if ((linkObj.has("href")
                                        && linkObj.has("rel")) && linkObj["rel"].asString == "http://openid.net/specs/connect/1.0/issuer"
                            ) {
                                // we found the issuer, return it

                                val href = linkObj["href"].asString

                                return if (identifier == href || identifier.startsWith("http")) {
                                    // try to avoid sending a URL as the login hint
                                    LoadingResult(null, href)
                                } else {
                                    // otherwise pass back whatever the user typed as a login hint
                                    LoadingResult(identifier, href)
                                }
                            }
                        }
                    }
                }
            } catch (e: JsonParseException) {
                logger.warn("Failure in fetching webfinger input", e.message)
            } catch (e: RestClientException) {
                logger.warn("Failure in fetching webfinger input", e.message)
            }

            // we couldn't find it!
            if (key.scheme == "http" || key.scheme == "https") {
                // if it looks like HTTP then punt: return the input, hope for the best
                logger.warn("Returning normalized input string as issuer, hoping for the best: $identifier")
                return LoadingResult(null, identifier)
            } else {
                // if it's not HTTP, give up
                logger.warn("Couldn't find issuer: $identifier")
                throw IllegalArgumentException()
            }
        }
    }

    companion object {
        /**
         * Logger for this class
         */
        private val logger: Logger = LoggerFactory.getLogger(WebfingerIssuerService::class.java)
    }
}
