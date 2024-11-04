package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.footer
import io.github.pdvrieze.openid.web.tags.header
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.*


fun HTML.login(
    context: WebContext,
    loginActionUrl: String,
    loginHint: String?,
    paramError: String?,
    redirectUri: String?,
) {
    val title = "Log In"//context.intl.messageText("login")
    val config = context.config
    val _csrf = context.csrf
    lang = context.lang
    head {
        header(context, title)
        script(type = "text/javascript") {
            val scopeTarget = if(loginHint != null) "j_password" else "j_username"
            unsafe { raw("\$(document).ready(function() {\$('$scopeTarget').focus();});") }
        }
    }
    body {
        div {
            id = "wrap"

            topBar(context)
            div("container-fluid main") {
                with(context.intl) {

                    h1() {message("login.login_with_username_and_password",  )}

                    if (paramError != null) {
                        div(classes="alert alert-error") {message("login.error")}
                    }


                    div(classes="row-fluid") {
                        div(classes="span6 offset1 well") {
                            form(action=loginActionUrl, method=FormMethod.post) {
                                div() {
                                    div(classes="input-prepend input-block-level") {
                                        span(classes = "add-on") { i(classes = "icon-user") }
                                        input(type=InputType.text,   name="username") {
                                            placeholder = messageText("login.username")
                                            attributes["autocorrect"] = "off"
                                            attributes["autocapitalize"] = "off"
                                            attributes["autocomplete"] = "off"
                                            attributes["spellcheck"] = "false"
                                            attributes["value"] = loginHint ?: ""
                                            id = "j_username"
                                        }
                                    }
                                }
                                div() {
                                    div("input-prepend input-block-level") {
                                        span("add-on") {i("icon-lock")}
                                        input(InputType.password, name="password") {
                                            placeholder=messageText("login.password")
                                            attributes["autocorrect"]="off"
                                            attributes["autocapitalize"]="off"
                                            attributes["autocomplete"]="off"
                                            attributes["spellcheck"]="false"
                                            id="j_password"
                                        }
                                    }
                                }
                                div() {
                                    _csrf.requireSession()
                                    if (redirectUri != null) {
                                        hiddenInput(name = "redirect") { value=redirectUri }
                                    }
                                    input(type=InputType.submit, classes="btn", name="submit") {
                                        value=messageText("login.login-button")
                                    }
                                }
                            }
                        }
                    }

                }
            }

            div { id = "push" }
        }
        footer(context )
    }
}
