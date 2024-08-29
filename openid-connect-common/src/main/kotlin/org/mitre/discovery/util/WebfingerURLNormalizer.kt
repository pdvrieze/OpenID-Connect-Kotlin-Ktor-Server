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

import org.mitre.util.getLogger
import org.springframework.util.StringUtils
import org.springframework.web.util.UriComponents
import org.springframework.web.util.UriComponentsBuilder
import java.util.regex.Pattern

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
    private val pattern: Pattern = Pattern.compile(
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
	fun normalizeResource(identifier: String?): UriComponents? {
        // try to parse the URI
        // NOTE: we can't use the Java built-in URI class because it doesn't split the parts appropriately

        if (identifier.isNullOrEmpty()) {
            logger.warn("Can't normalize null or empty URI: $identifier")
            return null // nothing we can do
        } else {
            // TODO URI's are not regular, replace with a proper parser (or use URI)
            //UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(identifier);

            val builder = UriComponentsBuilder.newInstance()

            val m = pattern.matcher(identifier)
            if (m.matches()) {
                builder.scheme(m.group(2))
                builder.userInfo(m.group(6))
                builder.host(m.group(8))
                val port = m.group(10)
                if (!port.isNullOrEmpty()) {
                    builder.port(port.toInt())
                }
                builder.path(m.group(11))
                builder.query(m.group(13))
                builder.fragment(m.group(15)) // we throw away the hash, but this is the group it would be if we kept it
            } else {
                // doesn't match the pattern, throw it out
                logger.warn("Parser couldn't match input: $identifier")
                return null
            }

            val n = builder.build()

            if (n.scheme.isNullOrEmpty()) {
                if ((!n.userInfo.isNullOrEmpty()
                            && n.path.isNullOrEmpty()
                            && n.query.isNullOrEmpty()) && n.port < 0
                ) {
                    // scheme empty, userinfo is not empty, path/query/port are empty
                    // set to "acct" (rule 2)

                    builder.scheme("acct")
                } else {
                    // scheme is empty, but rule 2 doesn't apply
                    // set scheme to "https" (rule 3)
                    builder.scheme("https")
                }
            }

            // fragment must be stripped (rule 4)
            builder.fragment(null)

            return builder.build()
        }
    }


    @JvmStatic
	fun serializeURL(uri: UriComponents): String {

        if (uri.scheme in SPECIAL_SCHEMES) {
            // serializer copied from HierarchicalUriComponents but with "//" removed

            val uriBuilder = StringBuilder()

            if (uri.scheme != null) {
                uriBuilder.append(uri.scheme)
                uriBuilder.append(':')
            }

            if (uri.userInfo != null || uri.host != null) {
                if (uri.userInfo != null) {
                    uriBuilder.append(uri.userInfo)
                    uriBuilder.append('@')
                }
                if (uri.host != null) {
                    uriBuilder.append(uri.host)
                }
                if (uri.port != -1) {
                    uriBuilder.append(':')
                    uriBuilder.append(uri.port)
                }
            }

            val path = uri.path
            if (StringUtils.hasLength(path)) {
                if (uriBuilder.length != 0 && path[0] != '/') {
                    uriBuilder.append('/')
                }
                uriBuilder.append(path)
            }

            val query = uri.query
            if (query != null) {
                uriBuilder.append('?')
                uriBuilder.append(query)
            }

            if (uri.fragment != null) {
                uriBuilder.append('#')
                uriBuilder.append(uri.fragment)
            }

            return uriBuilder.toString()
        } else {
            return uri.toUriString()
        }
    }

    private val SPECIAL_SCHEMES = hashSetOf("acct", "mailto", "tel", "device")
}
