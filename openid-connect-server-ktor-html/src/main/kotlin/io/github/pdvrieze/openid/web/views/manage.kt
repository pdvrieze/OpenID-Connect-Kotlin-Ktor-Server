package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.sidebar
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.ButtonType
import kotlinx.html.Entities
import kotlinx.html.TagConsumer
import kotlinx.html.button
import kotlinx.html.div
import kotlinx.html.h3
import kotlinx.html.id
import kotlinx.html.p
import kotlinx.html.role
import kotlinx.html.span
import kotlinx.html.style
import kotlinx.html.tabIndex

fun <T, C : TagConsumer<T>> C.manage(context: WebContext): T {
    val title = context.intl.messageText("manage.title")
    return formattedPage(context, title, js = true) {
        topBar(context, "Home")
        with(context.intl) {
            comment("Modal dialogue for management UI")
            div(classes = "modal hide fade") {
                id = "modalAlert"
                tabIndex = "-1"
                role = "dialog"
                div(classes = "modal-header") {
                    button(type = ButtonType.button, classes = "close") {
                        attributes["data-dismiss"] = "modal"
                        +Entities.times;
                    }
                    h3() { id = "modalAlertLabel" }
                }
                div(classes = "modal-body") {}
                div(classes = "modal-footer") {
                    button(classes = "btn btn-primary",) {
                        attributes["data-dismiss"] = "modal"
                        message("manage.ok",)
                    }
                }
            }

            div(classes = "container-fluid main") {
                div(classes = "row-fluid") {
                    sidebar(context)
                    div(classes = "span10") {
                        div(classes = "content span12") {
                            div() { id = "breadcrumbs" }
                            div(classes = "sheet hide fade",) {
                                id = "loadingbox"
                                attributes["data-sheet-parent"] = "#breadcrumbs"
                                div(classes = "sheet-body") {
                                    p() {
                                        message("manage.loading",)
                                        +":"
                                    }
                                    p() { span() { id = "loading" } }
                                }
                            }
                            div() {
                                id = "content"
                                div(classes = "well") {
                                    div() {
                                        h3() {
                                            message("manage.loading",)
                                            +"..."
                                        }
                                    }
                                    div(classes = "progress progress-striped active") {
                                        div(classes = "bar") { style = "width: 100%;" }
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }
    }
}
