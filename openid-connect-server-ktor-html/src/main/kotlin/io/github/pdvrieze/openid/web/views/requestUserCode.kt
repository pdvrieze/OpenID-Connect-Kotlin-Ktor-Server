package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.FormMethod
import kotlinx.html.HTML
import kotlinx.html.div
import kotlinx.html.form
import kotlinx.html.h1
import kotlinx.html.style
import kotlinx.html.submitInput
import kotlinx.html.textInput

fun HTML.requestUserCode(
    context: WebContext,
    error: String? = null
) {
    val _csrf = context.csrf
    with(context.intl) {
        val title = messageText("device.request_code.title")
        return formattedPage(context, title) {
            topBar(context, "Approve")
            div("container main") {
                div("well") {
                    style="text-align: center"

                    h1 {message("device.request_code.header",  )}

                    if (error != null) {
                        div("alert alert-error") {
                            when (error) {
                                "noUserCode" -> message("device.error.noUserCode")
                                "expiredUserCode" -> message("device.error.expiredUserCode")
                                "userCodeAlreadyApproved" -> message("device.error.userCodeAlreadyApproved")
                                "userCodeMismatch" -> message("device.error.userCodeMismatch")
                                else -> message("device.error.error")
                            }
                        }
                    }


                    form(context.issuerUrl("device/verify"), method=FormMethod.post) {

                        div("row-fluid") {
                            div("span12") {
                                val authorize_label = messageText("device.request_code.submit")
                                div {
                                    div("input-block-level input-xlarge") {
                                        textInput(name="user_code") {
                                            placeholder = "code"
                                            attributes["autocorrect"] = "off"
                                            attributes["autocapitalize"] = "off"
                                            attributes["autocomplete"] = "off"
                                            attributes["spellcheck"] = "false"
                                            value = ""
                                        }
                                    }
                                }
                                _csrf.requireSession()
                                /*input(InputType.hidden, name= _csrf.parameterName ) { value= _csrf.token }*/
                                submitInput(name = "approve", classes = "btn btn-info btn-large") {
                                    value = authorize_label
                                }
                            }
                        }

                    }

                }

            }
        }
    }
}
