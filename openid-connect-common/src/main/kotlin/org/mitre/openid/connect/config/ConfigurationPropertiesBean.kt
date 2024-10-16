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
package org.mitre.openid.connect.config

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.mitre.util.getLogger
import java.time.Duration
import java.util.*

/**
 * Bean to hold configuration information that must be injected into various parts
 * of our application. Set all of the properties here, and autowire a reference
 * to this bean if you need access to any configuration properties.
 *
 * @author AANGANES
 */
class ConfigurationPropertiesBean {
    var authCodeExpirationSeconds: Duration = Duration.ofMinutes(5)
    var jsFiles: Set<String> = emptySet()
    val projectVersion: String = "0.1 - BETA" // TODO("make this more dynamic")

    /**
     * the issuer baseUrl
     */
    lateinit var issuer: String

    val safeIssuer: String get() = when (issuer.last()) {
        '/' -> issuer
        else -> "$issuer/"
    }

    @Deprecated("Doesn't initialize issuer")
    constructor()
    constructor(issuer: String, topBarTitle: String = "Ktor OID Server") {
        this.issuer = issuer
        this.topbarTitle = topBarTitle
    }

    lateinit var topbarTitle: String

    private var _shortTopbarTitle: String? = null
    /**
     * @get If [shortTopbarTitle] is undefined, returns [topbarTitle].
     */
    var shortTopbarTitle: String
        get() = _shortTopbarTitle ?: topbarTitle
        set(value) {_shortTopbarTitle = value }

    var logoImageUrl: String? = null

    /**
     * The registration token lifetime to set in seconds
     */
    var regTokenLifeTime: Long? = null

    var rqpTokenLifeTime: Long? = null

    var isForceHttps: Boolean = false // by default we just log a warning for HTTPS deployment

    var locale: Locale = Locale.ENGLISH // we default to the english translation

    var languageNamespaces: List<String> = listOf("messages", "uma")

    /**
     * The dual client configuration. `true` if dual client is configured, otherwise `false`
     */
    var isDualClient: Boolean = false
        get() = !isHeartMode && field // HEART mode is incompatible with dual client mode

    var isHeartMode: Boolean = false

    var isAllowCompleteDeviceCodeUri: Boolean = false

    /**
     * Endpoints protected by TLS must have https scheme in the URI.
     * @throws HttpsUrlRequiredException
     */
    //@PostConstruct
    fun checkConfigConsistency() {
        if (!issuer.startsWith("https", ignoreCase = true)) {
            if (this.isForceHttps) {
                logger.error("Configured issuer url is not using https scheme. Server will be shut down!")
                throw IllegalStateException("Issuer is not using https scheme as required: $issuer")
            } else {
                logger.warn("\n\n**\n** WARNING: Configured issuer url is not using https scheme.\n**\n\n")
            }
        }

        if (languageNamespaces.isEmpty()) {
            logger.error("No configured language namespaces! Text rendering will fail!")
        }
    }

    /**
     * The list of namespaces as a JSON string, for injection into the JavaScript UI
     */
    val languageNamespacesString: String
        get() = Json.encodeToString(languageNamespaces)

    /**
     * Get the default namespace (first in the nonempty list)
     */
    val defaultLanguageNamespace: String
        get() = languageNamespaces.first()

    companion object {
        /**
         * Logger for this class
         */
        @JvmStatic
        private val logger = getLogger<ConfigurationPropertiesBean>()
    }
}
