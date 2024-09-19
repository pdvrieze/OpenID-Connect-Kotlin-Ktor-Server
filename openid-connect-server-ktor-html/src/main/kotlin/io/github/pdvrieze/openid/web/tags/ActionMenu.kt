package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HtmlTagMarker
import kotlinx.html.UL
import kotlinx.html.li
import org.mitre.oauth2.web.AuthenticationUtilities

@HtmlTagMarker
fun UL.actionMenu(context: WebContext) {
    with(context.intl) {
        if (AuthenticationUtilities.hasRole(context.authentication, "ROLE_ADMIN")) {
            li("nav-header") { message("sidebar.administrative.title") }

            li { a_data(href = "manage/#admin/clients") { message("sidebar.administrative.manage_clients") } }
            li { a_data(href = "manage/#admin/whitelists") { message("sidebar.administrative.whitelisted_clients") } }
            li { a_data(href = "manage/#admin/blacklist") { message("sidebar.administrative.blacklisted_clients") } }
            li { a_data(href = "manage/#admin/scope") { message("sidebar.administrative.system_scopes") } }
            li("divider")
        }

        li("nav-header") { message("sidebar.personal.title") }
        li { a_data(href = "manage/#user/approved") { message("sidebar.personal.approved_sites")} }
        li { a_data(href = "manage/#user/tokens") { message("sidebar.personal.active_tokens")} }
        li { a_data(href = "manage/#user/profile") { message("sidebar.personal.profile_information")} }
        li("divider")

        li("nav-header") { message("sidebar.developer.title") }
        li { a_data(href = "manage/#dev/dynreg") { message("sidebar.developer.client_registration")} }
        li { a_data(href = "manage/#dev/resource") { message("sidebar.developer.resource_registration")} }

    }

}
