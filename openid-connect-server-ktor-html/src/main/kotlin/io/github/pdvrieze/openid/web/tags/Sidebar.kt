package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.FlowContent
import kotlinx.html.HtmlTagMarker
import kotlinx.html.div
import kotlinx.html.ul
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.web.AuthenticationUtilities

@HtmlTagMarker
fun FlowContent.sidebar(context: WebContext) {
    if(AuthenticationUtilities.hasRole(context.authentication, GrantedAuthority.ROLE_USER)) {
        div("span2 visible-desktop") {
            div("well sidebar-nav") {
                ul("nav nav-list") {
                    actionMenu(context)
                }
            }
        }
    } else {
        div("span1") { comment("placeholder for non-logged-in users")}
    }
}
