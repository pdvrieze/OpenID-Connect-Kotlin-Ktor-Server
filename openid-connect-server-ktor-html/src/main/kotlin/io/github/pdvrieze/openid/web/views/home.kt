package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.Entities
import kotlinx.html.HTML
import kotlinx.html.a
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.h2
import kotlinx.html.hr
import kotlinx.html.id
import kotlinx.html.img
import kotlinx.html.p

fun HTML.home(context: WebContext) {
    val title = context.intl.messageText("home.title")
    return baseView(context, title, "Home", true, extraJs = EXTRA_JS) {
        with(context.intl) {
            div(classes = "span10") {
                div(classes = "hero-unit") {
                    div(classes = "row-fluid") {
                        div(classes = "span2 visible-desktop") { img(src="resources/images/openid_connect_large.png") }

                        div(classes = "span10") {
                            h1 { message("home.welcome.title",) }
                            p { message("home.welcome.body",) }
                        }
                    }
                }
                comment("Example row of columns")
                div(classes = "row-fluid") {
                    div(classes = "span6") {
                        h2 { message("home.about.title",) }

                        p { message("home.about.body",) }

                        p {
                            a("http://github.com/mitreid-connect/", classes = "btn") {
                                message("home.more")
                                +Entities.raquo
                            }
                        }
                    }
                    div(classes = "span6") {
                        h2 { message("home.contact.title",) }
                        p { message("home.contact.body") }
                    }

                }
                hr {
                    comment("Example row of columns")
                    div("row-fluid") {
                        div("span12") {
                            h2 { message("home.statistics.title",) }

                            p("muted") {
                                id = "statsloader"
                                message("home.statistics.loading")
                            }

                            p {
                                id = "stats"
                                message("home.statistics.number_users", "?")
                                message("home.statistics.number_clients", "?")
                                message("home.statistics.number_approvals", "?")
                            }
                        }
                    }

                }

            }
        }
    }
}

val EXTRA_JS: String = """|// load stats dynamically to make main page render faster
                |
                |${'$'}(document).ready(function() {
                |		${'$'}('#stats').hide();
                |		var base = ${'$'}('base').attr('href');
                |		if (base.substr(-1) !== '/') {
                |			base += '/';
                |		}
                |
                |        ${'$'}.getJSON(base + 'api/stats/summary', function(data) {
                |        	var stats = data;
                |        	${'$'}('#userCount').html(stats.userCount);
                |        	${'$'}('#clientCount').html(stats.clientCount);
                |        	${'$'}('#approvalCount').html(stats.approvalCount);
                |        	${'$'}('#statsloader').hide();
                |        	${'$'}('#stats').show();
                |        	
                |        });
                |});
                |""".trimMargin()

