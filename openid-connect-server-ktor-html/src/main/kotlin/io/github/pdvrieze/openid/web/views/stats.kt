package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HTML
import kotlinx.html.div
import kotlinx.html.h2
import kotlinx.html.p


//comment("TODO: highlight proper section of topbar; what is the right way to do this?")

fun HTML.stats(
    context: WebContext,
    statsSummary: Map<String, Int>
) {
    with(context.intl) {
        val title = messageText("statistics.title")
        return baseView(context, title, "Statistics", true) {
            div(classes = "span10") {
                div(classes = "hero-unit") {
                    h2() { message("statistics.title") }

                    p() {
                        message("statistics.number_users", statsSummary["userCount"])
                        message("statistics.number_clients", statsSummary["clientCount"])
                        message("statistics.number_approvals", statsSummary["approvalCount"])
                    }
                }
            }
        }
    }
}
