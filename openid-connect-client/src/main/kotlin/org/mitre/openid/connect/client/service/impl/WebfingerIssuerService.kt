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

import com.google.common.util.concurrent.UncheckedExecutionException
import io.github.pdvrieze.client.CoroutineCache
import io.github.pdvrieze.client.onError
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.util.*
import io.ktor.utils.io.errors.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import org.mitre.discovery.util.WebfingerURLNormalizer.normalizeResource
import org.mitre.openid.connect.client.AuthenticationServiceException
import org.mitre.openid.connect.client.model.IssuerServiceResponse
import org.mitre.openid.connect.client.service.IssuerService
import org.mitre.util.asString
import org.mitre.util.getLogger
import java.util.concurrent.ExecutionException

/**
 * Use Webfinger to discover the appropriate issuer for a user-given input string.
 * @author jricher
 */
class WebfingerIssuerService(
    private val httpClient: HttpClient = HttpClient(CIO)
) : IssuerService {

    // map of user input -> issuer, loaded dynamically from webfinger discover
    private val issuers = CoroutineCache<String, LoadingResult>(::fetch)

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

    override suspend fun getIssuer(requestParams: Map<String, List<String>>, requestUrl: String): IssuerServiceResponse? {
        val identifier: String? = requestParams[parameterName]?.firstOrNull()
        val targetLinkUri: String? = requestParams["target_link_uri"]?.firstOrNull()

        if (!identifier.isNullOrEmpty()) {
            try {
                val lr = issuers.load(identifier)
                if (!whitelist.isEmpty() && !whitelist.contains(lr.issuer)) {
                    throw AuthenticationServiceException("Whitelist was nonempty, issuer was not in whitelist: " + lr.issuer)
                }

                if (blacklist.contains(lr.issuer)) {
                    throw AuthenticationServiceException("Issuer was in blacklist: " + lr.issuer)
                }

                return IssuerServiceResponse(lr.issuer, lr.loginHint, targetLinkUri)
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

    @Throws(Exception::class)
    private suspend fun fetch(identifier: String): LoadingResult {
        val key = normalizeResource(identifier)

        // construct the URL to go to
        val rawScheme = key!!.scheme

        val scheme: URLProtocol

        // preserving http scheme is strictly for demo system use only.
        if (!rawScheme.isNullOrEmpty() && rawScheme == "http") {
            // add on colon and slashes.
            require(!isForceHttps) { "Scheme must not be 'http'" }
            logger.warn("Webfinger endpoint MUST use the https URI scheme, overriding by configuration")
            scheme = URLProtocol.HTTP // add on colon and slashes.
        } else {
            // otherwise we don't know the scheme, assume HTTPS
            scheme = URLProtocol.HTTPS
        }

        // do a webfinger lookup
        val url = url {
            protocol = scheme
            host = key.host
            if (key.port >=0) port = key.port
            path(key.path?:"")

            parameters {
                val q = key.query
                if (!q.isNullOrEmpty()) {
                    appendAll(parseQueryString(q))
                }

                append("resource", identifier)
                append("rel", "http://openid.net/specs/connect/1.0/issuer")
            }
        }



        try {
            // do the fetch

            logger.info("Loading: $url")

            val webfingerResponse = httpClient.get(url).onError { throw IOException("Could not load $url, $it") }

            val json = Json.parseToJsonElement(webfingerResponse.bodyAsText())

            if (json is JsonObject) {
                // find the issuer
                val links = json["links"]!!.jsonArray
                for (link in links) {
                    if (link is JsonObject) {

                        if (("href" in link && "rel" in link) && link["rel"].asString() == "http://openid.net/specs/connect/1.0/issuer"
                        ) {
                            // we found the issuer, return it

                            val href = link["href"].asString()

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
        } catch (e: SerializationException) {
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


    companion object {
        /**
         * Logger for this class
         */
        private val logger = getLogger<WebfingerIssuerService>()
    }
}
