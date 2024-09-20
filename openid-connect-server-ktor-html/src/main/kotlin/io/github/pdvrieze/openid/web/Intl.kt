package io.github.pdvrieze.openid.web

import kotlinx.html.HTMLTag
import kotlinx.html.unsafe

interface Intl {
    fun HTMLTag.message(key: String, vararg args: Any?) {
        // use unsafe as the text may contain html elements
        unsafe { raw(messageText(key, args)) }
    }
    fun messageText(key: String, vararg args: Any?): String
}
