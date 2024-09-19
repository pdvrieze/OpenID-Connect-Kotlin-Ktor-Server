package io.github.pdvrieze.openid.web

import kotlinx.html.FlowOrPhrasingContent
import kotlinx.html.PhrasingContent

interface Intl {
    fun FlowOrPhrasingContent.message(key: String, vararg args: Any?)
    fun messageText(key: String, vararg args: Any?): String
}
