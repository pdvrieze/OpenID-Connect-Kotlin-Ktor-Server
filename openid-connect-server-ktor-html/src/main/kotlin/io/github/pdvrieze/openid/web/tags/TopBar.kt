package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.*
import org.mitre.oauth2.web.AuthenticationUtilities

@HtmlTagMarker
fun FlowContent.topBar(context: WebContext, pageName: String?) {
    val userInfo = context.userInfo
    val shortName = userInfo?.preferredUsername
        ?: userInfo?.subject
        ?: "<Unknown name>"

    val longName = when(userInfo) {
        null -> shortName
        else -> userInfo.name ?: run {
            val givenName = userInfo.givenName
            val familyName = userInfo.familyName
            when {
                givenName == null -> familyName ?: shortName
                familyName != null -> "$givenName $familyName"
                else -> givenName
            }
        }
    }

    val isUser = AuthenticationUtilities.hasRole(context.authentication, "ROLE_USER")

    div("navbar navbar-fixed-top") {
        div("navbar-inner") {
            div("container") {
/*
<div class="navbar navbar-fixed-top">
	<div class="navbar-inner">
		<div class="container">
*/
                button(classes = "btn btn-navbar") {
                    attributes["data-toggle"] = "collapse"
                    attributes["data-target"] = ".nav-collapse"

                    span("icon-bar")
                    span("icon-bar")
                    span("icon-bar")
                }
                a("", classes = "brand") {
                    img(src = context.config.logoImageUrl)
                    span {
                        span("visible-phone") { this.text(context.config.shortTopbarTitle) }
                        span("hidden-phone") { this.text(context.config.topbarTitle) }
                    }
                }
                if(! pageName.isNullOrBlank()) {
                    div("nav-collapse collapse") {
/*
			<c:if test="${ not empty pageName }">
				<div class="nav-collapse collapse">
*/
                        ul("nav") {
                            navmenu(context, pageName)
                        }
                        if (isUser) {
                            ul("nav hidden-desktop") {
                                actionMenu(context)
                            }
                        }

                        ul(classes = "nav pull-right visible-desktop") {
                            if(isUser) {
                                li("dropdown") {
                                    a_data(href = "", classes = "dropdown-toggle", dataToggle = "dropdown", dataTarget = null) {
                                        id="userButton"
                                        i("icon-user icon-white")
                                        +shortName
                                        span("caret")
                                    }
                                    ul("dropdown-menu pull-right") {
                                        li { a_data("manage/#user/profile") { +longName }}
                                        li("divider")
                                        li {
                                            a_data("", classes = "logoutlink") {
                                                i(classes = "icon-remove")
                                                with(context.intl) { message("topbar.logout") }
                                            }
                                        }
                                    }
                                }
                            } else {
                                li {
                                    a_data("login") {
                                        id = "loginButton"
                                        i("icon-lock icon-white")
                                        with(context.intl) { message("topbar.login") }
                                    }
                                }
                            }
                        }

                        comment("use a simplified user button system when collapsed")

                        ul(classes = "nav hidden-desktop") {
                            if(isUser) {
                                li { a(href = "manage/#user/profile") { +longName } }
                                li("divider")
                                li {
                                    a("", classes = "logoutlink") {
                                        i(classes = "icon-remove")
                                        with(context.intl) { message("topbar.logout") }
                                    }
                                }

                            } else {
                                li {
                                    a_data("login") {
                                        id = "loginButton"
                                        i("icon-lock icon-white")
                                        with(context.intl) { message("topbar.login") }
                                    }
                                }
                            }
                        }

                        form(
                            action = context.issuerUrl("logout"),
                            method = FormMethod.post,
                            classes = "hidden",
                        ) {
                            id= "logoutForm"
/*
                            input(type = InputType.hidden, name = context.csrf.parameterName) { value = context.csrf.token }
*/
                        }

                    }
                }
            }
        }

        script(type = "text/javascript") {
            unsafe {
                raw("""
                |    ${'$'}(document).ready(function() {
                |        ${'$'}('.logoutLink').on('click', function(e) {
                |            e.preventDefault();
                |            ${'$'}('#logoutForm').submit();
                |        });
                |    });""".trimMargin())
            }
        }
    }
}
