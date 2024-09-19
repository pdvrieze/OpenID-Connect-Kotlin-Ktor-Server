package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.sidebar
import kotlinx.html.TagConsumer
import kotlinx.html.div
import kotlinx.html.h2
import kotlinx.html.p

// TODO: highlight proper section of topbar; what is the right way to do this?
fun <T, C : TagConsumer<T>> C.about(context: WebContext): T {
    val title = context.intl.messageText("about.title")
    return baseView(context, title, "About", true) {
        sidebar(context)

        div("span10") {
            comment("Main hero unit for a primary marketing message or call to action")
            div("hero-unit") {
                h2 { +title }
                p { with(context.intl) { message("about.body") } }
            }
        }
    }
}
