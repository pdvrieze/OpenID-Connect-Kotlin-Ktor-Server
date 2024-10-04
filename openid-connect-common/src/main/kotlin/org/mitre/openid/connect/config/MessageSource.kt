package org.mitre.openid.connect.config

import java.text.MessageFormat
import java.util.*

interface MessageSource {
    fun resolveCode(code: String, locale: Locale): MessageFormat?
}
