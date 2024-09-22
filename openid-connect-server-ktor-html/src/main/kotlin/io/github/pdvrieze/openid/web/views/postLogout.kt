package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.HTML
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.style
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.web.AuthenticationUtilities

fun HTML.postLogout(context: WebContext) {
    with(context.intl) {
        val title = messageText("logout.post.title")
        return formattedPage(context, title) {
            topBar(context)
            div(classes="container main") {

                div(classes="well", ) {
                    style="text-align: center"
                    h1() { message("logout.post.header")}
                    div {
                        val a = context.authentication
                        if (a != null && GrantedAuthority.ROLE_USER !in a.authorities) {
                            message("logout.post.notLoggedOut")
                        } else {
                            message("logout.post.loggedOut")
                        }

                    }
                }
            }

        }
    }
}
