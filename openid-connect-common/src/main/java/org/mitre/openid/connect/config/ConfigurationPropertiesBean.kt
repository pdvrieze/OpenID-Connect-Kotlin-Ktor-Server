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

import com.google.common.collect.Lists
import com.google.gson.Gson
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanCreationException
import org.springframework.util.StringUtils
import java.util.*
import javax.annotation.PostConstruct

/**
 * Bean to hold configuration information that must be injected into various parts
 * of our application. Set all of the properties here, and autowire a reference
 * to this bean if you need access to any configuration properties.
 *
 * @author AANGANES
 */
class ConfigurationPropertiesBean {
    /**
     * the issuer baseUrl
     */
    lateinit var issuer: String

    var topbarTitle: String? = null

    /**
     * @get If [shortTopbarTitle] is undefined, returns [topbarTitle].
     */
    var shortTopbarTitle: String? = null
        get() = field ?: topbarTitle

    var logoImageUrl: String? = null

    /**
     * The registration token lifetime to set in seconds
     */
    var regTokenLifeTime: Long? = null

    var rqpTokenLifeTime: Long? = null

    var isForceHttps: Boolean = false // by default we just log a warning for HTTPS deployment

    var locale: Locale = Locale.ENGLISH // we default to the english translation

    var languageNamespaces: List<String>? = listOf("messages")

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
    @PostConstruct
    fun checkConfigConsistency() {
        if (!issuer.startsWith("https", ignoreCase = true)) {
            if (this.isForceHttps) {
                logger.error("Configured issuer url is not using https scheme. Server will be shut down!")
                throw BeanCreationException("Issuer is not using https scheme as required: $issuer")
            } else {
                logger.warn("\n\n**\n** WARNING: Configured issuer url is not using https scheme.\n**\n\n")
            }
        }

        if (languageNamespaces.isNullOrEmpty()) {
            logger.error("No configured language namespaces! Text rendering will fail!")
        }
    }

    /**
     * The list of namespaces as a JSON string, for injection into the JavaScript UI
     */
    val languageNamespacesString: String
        get() = Gson().toJson(languageNamespaces)

    /**
     * Get the default namespace (first in the nonempty list)
     */
    val defaultLanguageNamespace: String
        get() = languageNamespaces!!.first()

    companion object {
        /**
         * Logger for this class
         */
        @JvmStatic
        private val logger: Logger = LoggerFactory.getLogger(ConfigurationPropertiesBean::class.java)
    }
}
