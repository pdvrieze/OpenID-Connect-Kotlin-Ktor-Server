package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.Entities
import kotlinx.html.FormMethod
import kotlinx.html.HTML
import kotlinx.html.InputType
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h1
import kotlinx.html.input
import kotlinx.html.style
import org.mitre.oauth2.model.OAuthClientDetails

fun HTML.logoutConfirmation(
    context: WebContext,
    client: OAuthClientDetails?,
) {
    val title = context.intl.messageText("logout.confirmation.title")
    val clientName = client?.clientName?.takeUnless { it.isBlank() }
    val clientId = client?.clientId
    val _csrf = context.csrf

    formattedPage(context, title ) {
        topBar(context, )
        div("container main") {
            with(context.intl) {
                div(classes="well") {
                    style="text-align: center"

                    h1 { message("logout.confirmation.header") }

                    form(action=context.issuerUrl("endsession"), method=FormMethod.post) {

                        div(classes="row-fluid") {
                            div(classes="span12") {

                                div {
                                    if (client != null) {
                                        comment("display some client information")
                                        message("logout.confirmation.requested",  )
                                        +Entities.nbsp
                                        +(clientName ?: clientId!!)
                                    }
                                }
                                div { message("logout.confirmation.explanation") }
                                clientId?.let { input(InputType.hidden, name="clientId") { value = it } }
                                input(InputType.hidden, name = _csrf.parameterName) {
                                    value= _csrf.token
                                }
                                input(InputType.submit, name = "approve", classes = "btn btn-info btn-large") {
                                    value = messageText("logout.confirmation.submit")
                                }
                                +Entities.nbsp
                                input(name="deny", type=InputType.submit, classes="btn btn-large" ) {
                                    value = messageText("logout.confirmation.deny")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
