package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HTML
import kotlinx.html.div
import kotlinx.html.h2
import kotlinx.html.p

// comment("TODO: highlight proper section of topbar; what is the right way to do this?")
fun HTML.contact(context: WebContext) {
    val title = context.intl.messageText("contact.title")
    return baseView(context, title, "Contact", true) {
        with(context.intl) {
            div(classes = "span10") {
                div(classes = "hero-unit") {
                    h2 { message("contact.title") }
                    p { message("contact.body") }
                }
            }
        }
    }
}
