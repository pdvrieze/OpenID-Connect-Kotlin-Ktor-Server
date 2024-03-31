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

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.i18n.LocaleContext
import org.springframework.context.i18n.TimeZoneAwareLocaleContext
import org.springframework.stereotype.Component
import org.springframework.web.servlet.i18n.AbstractLocaleContextResolver
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * Resolve the server's locale from the injected ConfigurationPropertiesBean.
 *
 * @author jricher
 */
@Component
class ConfigurationBeanLocaleResolver : AbstractLocaleContextResolver() {
    @Autowired
    private lateinit var config: ConfigurationPropertiesBean

    override fun getDefaultLocale(): Locale? {
        return config.locale
    }

    override fun resolveLocaleContext(request: HttpServletRequest): LocaleContext {
        return object : TimeZoneAwareLocaleContext {
            override fun getLocale(): Locale? {
                return defaultLocale
            }

            override fun getTimeZone(): TimeZone? {
                return defaultTimeZone
            }
        }
    }

    override fun setLocaleContext(
        request: HttpServletRequest,
        response: HttpServletResponse?,
        localeContext: LocaleContext?
    ) {
        throw UnsupportedOperationException("Cannot change fixed locale - use a different locale resolution strategy")
    }
}
