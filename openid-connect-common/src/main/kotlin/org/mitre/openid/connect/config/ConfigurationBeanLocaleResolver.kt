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
package org.mitre.openid.connect.config

import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Resolve the server's locale from the injected ConfigurationPropertiesBean.
 *
 * @author jricher
 */
class ConfigurationBeanLocaleResolver {
    private lateinit var config: ConfigurationPropertiesBean

    val defaultLocale: Locale?
        get() {
            return config.locale
        }

    var defaultTimeZone: TimeZone? = null

    fun resolveLocaleContext(request: HttpServletRequest): LocaleContext {
        return object : TimeZoneAwareLocaleContext {
            override val locale: Locale? get() = defaultLocale

            override val timeZone: TimeZone? get() = defaultTimeZone
        }
    }

    interface LocaleContext {
        val locale: Locale?
    }

    interface TimeZoneAwareLocaleContext : LocaleContext {

        val timeZone: TimeZone?
    }
}
