package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HTML
import kotlinx.html.div
import kotlinx.html.h2
import kotlinx.html.p

// TODO: highlight proper section of topbar; what is the right way to do this?
fun HTML.about(context: WebContext) {
    val title = context.intl.messageText("about.title")
    baseView(context, title, "About", hasSideBar = true) {
        div("span10") {
            comment("Main hero unit for a primary marketing message or call to action")
            div("hero-unit") {
                h2 { +title }
                p { with(context.intl) { message("about.body") } }
            }
        }
    }
}
