package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.footer
import io.github.pdvrieze.openid.web.header
import kotlinx.html.DIV
import kotlinx.html.HtmlTagMarker
import kotlinx.html.TagConsumer
import kotlinx.html.body
import kotlinx.html.div
import kotlinx.html.head
import kotlinx.html.html
import kotlinx.html.id
import kotlinx.html.lang

@HtmlTagMarker
inline fun <T, C : TagConsumer<T>> C.formattedPage(context: WebContext, title: String, crossinline content: DIV.(WebContext) -> Unit): T {
    return html {
        lang = context.lang
        head {
            header(context, title)
        }
        body {
            div {
                id="wrap"

                content(context)

                div { id="push" }
            }
            footer(context)
        }
    }
}
