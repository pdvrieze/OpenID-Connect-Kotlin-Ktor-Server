package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.TagConsumer
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.i
import kotlinx.html.style
import org.mitre.oauth2.model.OAuthClientDetails

fun <T, C : TagConsumer<T>> C.deviceApproved(
    context: WebContext,
    client: OAuthClientDetails,
    approved: Boolean,
): T {
    val title = context.intl.messageText("approve.title")
    val clientName = client.clientName?.takeUnless { it.isBlank() }
    val clientId = client.clientId
    return formattedPage(context, title) {
        with(context.intl) {
            topBar(context, "Approve")
            div("container main") {
                div(classes="well") {
                    style = "text-align: center"
                    h1 { +(clientName ?: clientId!!) }

                    when {
                        approved -> div(classes = "text-success") {
                            i(classes = "icon-ok")
                            message("device.approve.approved")
                        }

                        else -> div(classes = "text-error") {
                            i(classes = "icon-remove")
                            message("device.approve.notApproved")
                        }

                    }

                }

            }
        }
    }
}
