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
import java.net.URI

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
	fun normalizeResource(identifier: String?): ExtUri? {
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

            var matchedScheme = m.groups[2]?.value
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
                    matchedScheme = "https"
                }
            }

            return when(matchedScheme) {
                "acct" -> {
                    val authorityExt= buildString {
                        if (matchedPort!=null) append(':').append(matchedPort.toString())
                        if (matchedPath!=null) append(matchedPath)
                        m.groups[12]?.let { append(it.value) }
                    }.takeIf { it.isNotEmpty() }

                    ExtUri.Acct(requireNotNull(matchedUserInfo), requireNotNull(matchedHost), authorityExt)
                }
                "mailto" -> {
                    val authorityExt= buildString {
                        if (matchedPort!=null) append(':').append(matchedPort.toString())
                        if (matchedPath!=null) append(matchedPath)
                    }.takeIf { it.isNotEmpty() }

                    val fields = matchedQuery?.run {
                        split('&').associate {
                            val eqPos = it.indexOf('=')
                            when {
                                eqPos<0 -> it to null
                                else -> it.substring(0, eqPos) to it.substring(eqPos + 1)
                            }
                        }
                    }
                        ?: emptyMap()
                    ExtUri.MailTo(requireNotNull(matchedUserInfo), requireNotNull(matchedHost), authorityExt, headerFields = fields)
                }
                "tel" -> {
                    val ssp = (m.groups[4]?.value ?: "")+(matchedPath?:"") + (m.groups[12]?.value?:"")
                    ExtUri.Tel(ssp)
                }
                "device" -> {
                    ExtUri.Device(m.groups[4]?.value?:"", matchedPath, matchedQuery)
                }
                else -> ExtUri.Url(URI(matchedScheme, matchedUserInfo, matchedHost, matchedPort ?: -1, matchedPath, matchedQuery, null))
            }
        }
    }


    @JvmStatic
	fun serializeURL(uri: ExtUri): String {
        return uri.toString()
    }

    private val SPECIAL_SCHEMES = hashSetOf("acct", "mailto", "tel", "device")
    private val ACCT_SCHEME = "acct"
}

sealed class ExtUri {

    abstract val scheme: String

    data class Url(val uri: URI) : ExtUri() {
        constructor(uri: String): this(URI.create(uri))

        override val scheme: String get() = uri.scheme

        override fun toString() = uri.toString()
    }

    data class Acct(val userInfo: String, val domain: String, val authorityExt: String? = null) : ExtUri() {
        override val scheme: String
            get() = "acct"

        override fun toString() = when(authorityExt) {
            null -> "acct:$userInfo@$domain"
            else -> "acct:$userInfo@$domain$authorityExt"
        }
    }

    data class MailTo(val userInfo: String, val domain: String, val authorityExt: String? =null, val headerFields: Map<String, String?> = emptyMap()) : ExtUri() {
        override val scheme: String
            get() = "mailto"

        override fun toString(): String = buildString {
            append("mailto:")
            append(userInfo)
            append('@')
            append(domain)
            if (authorityExt != null) append(authorityExt)
            if (headerFields.isNotEmpty()) {
                headerFields.entries.joinTo(this, separator = "&", prefix = "?") { (k, v) ->
                    if (v==null) k else "$k=$v"
                }
            }
        }
    }

    data class Tel(val telNumber: String): ExtUri() {
        override val scheme: String
            get() = "tel"

        override fun toString(): String = "tel:$telNumber"
    }

    data class Device(val host: String, val path: String? = null, val query: String? = null): ExtUri() {
        override val scheme: String
            get() = "device"

        override fun toString(): String = buildString {
            append("device:")
            append(host)
            if (path != null) { append(path) }
            if (query != null) { append('?').append(query) }
        }
    }
}
