package io.github.pdvrieze.openid.web

import kotlinx.html.HtmlBlockTag

interface Intl {
    fun HtmlBlockTag.message(key:String) {
        consumer.onTagContentUnsafe { raw(messageText(key)) }
    }

    fun HtmlBlockTag.message(key: String, vararg args: Any?) {
        // use unsafe as the text may contain html elements. Note that the .unsafe function doesn't work as that
        // requires an Html tag
        consumer.onTagContentUnsafe { raw(messageText(key, *args)) }
    }

    fun messageText(key: String): String
    fun messageText(key: String, vararg args: Any?): String
}
