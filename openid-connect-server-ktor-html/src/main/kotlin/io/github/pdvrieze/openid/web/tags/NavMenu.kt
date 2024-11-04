package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.A
import kotlinx.html.HtmlTagMarker
import kotlinx.html.UL
import kotlinx.html.li

@HtmlTagMarker
private inline fun UL.navMenuItem(isActive: Boolean, url: String, crossinline message: A.() -> Unit) {
    when {
        isActive -> li("active") { a_data(href = "") { message() } }
        else -> li { a_data(href = url) { message() } }
    }
}

@HtmlTagMarker
fun UL.navmenu(context: WebContext, pageName: String) {
    with(context.intl) {
        navMenuItem(pageName=="Home", "") { message("topbar.home") }
        navMenuItem(pageName=="About", "about") { message("topbar.about") }
        navMenuItem(pageName=="Statistics", "stats") { message("topbar.statistics") }
        navMenuItem(pageName=="Contact", "contact") { message("topbar.contact") }
    }
}
