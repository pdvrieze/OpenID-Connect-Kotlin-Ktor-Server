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
package org.mitre.discovery.util

import io.ktor.http.*
import org.mitre.util.getLogger

/**
 * Provides utility methods for normalizing and parsing URIs for use with Webfinger Discovery.
 *
 * @author wkim
 */
object WebfingerURLNormalizer {
    /**
     * Logger for this class
     */
    private val logger = getLogger()

    // pattern used to parse user input; we can't use the built-in java URI parser
    private val pattern: Regex = Regex(
        "^" +
                "((https|acct|http|mailto|tel|device):(//)?)?" +  // scheme
                "(" +
                "(([^@]+)@)?" +  // userinfo
                "(([^\\?#:/]+)" +  // host
                "(:(\\d*))?)" +  // port
                ")" +
                "([^\\?#]+)?" +  // path
                "(\\?([^#]+))?" +  // query
                "(#(.*))?" +  // fragment
                "$"
    )


    /**
     * Normalize the resource string as per OIDC Discovery.
     * @return the normalized string, or null if the string can't be normalized
     */
	@JvmStatic
	fun normalizeResource(identifier: String?): Url? {
        // try to parse the URI
        // NOTE: we can't use the Java built-in URI class because it doesn't split the parts appropriately

        if (identifier.isNullOrEmpty()) {
            logger.warn("Can't normalize null or empty URI: $identifier")
            return null // nothing we can do
        } else {
            // TODO URI's are not regular, replace with a proper parser (or use URI)
            //UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(identifier);

            val m = pattern.matchEntire(identifier)
            if (m == null) {
                // doesn't match the pattern, throw it out
                logger.warn("Parser couldn't match input: $identifier")
                return null
            }

            var matchedScheme = m.groups[2]?.let { URLProtocol.createOrDefault(it.value) }
            val matchedUserInfo = m.groups[6]?.value
            val matchedHost = m.groups[8]?.value
            val matchedPort = when(val p = m.groups[10]?.value) {
                null, "" -> null
                else -> p.toInt()
            }
            val matchedPath = m.groups[11]?.value
            val matchedQuery: String? = m.groups[13]?.value

//            val n = builder.build()

            if (matchedScheme == null) {
                if ((!matchedUserInfo.isNullOrEmpty()
                            && matchedPath.isNullOrEmpty()
                            && matchedQuery.isNullOrEmpty()) && matchedPort == null
                ) {
                    // scheme empty, userinfo is not empty, path/query/port are empty
                    // set to "acct" (rule 2)
                    matchedScheme = ACCT_SCHEME
                } else {
                    // scheme is empty, but rule 2 doesn't apply
                    // set scheme to "https" (rule 3)
                    matchedScheme = URLProtocol.HTTPS
                }
            }

            val parameters: Parameters = matchedQuery?.let { parseQueryString(it) } ?: Parameters.Empty


            return URLBuilder(
                protocol = matchedScheme,
                host = matchedHost ?: "",
                port = matchedPort ?: DEFAULT_PORT,
                user = matchedUserInfo?.substringBefore(':'),
                password = matchedUserInfo?.substringAfter(':'),
                parameters = parameters,
                fragment = "",// fragment must be stripped (rule 4)
            ).apply {
                set(path = matchedPath)
            }.build()
        }
    }


    @JvmStatic
	fun serializeURL(uri: Url): String {
        return uri.toString()
    }

    private val SPECIAL_SCHEMES = hashSetOf("acct", "mailto", "tel", "device")
    private val ACCT_SCHEME = URLProtocol.createOrDefault("acct")
}
