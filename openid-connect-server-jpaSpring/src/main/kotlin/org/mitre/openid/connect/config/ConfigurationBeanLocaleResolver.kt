package org.mitre.openid.connect.config

import java.util.*

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
