package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.DIV
import kotlinx.html.HTML
import kotlinx.html.HtmlTagMarker
import kotlinx.html.body
import kotlinx.html.div
import kotlinx.html.head
import kotlinx.html.id
import kotlinx.html.lang

@HtmlTagMarker
@PublishedApi
internal inline fun HTML.formattedPage(context: WebContext, title: String, js: Boolean = false, extraJs: String? = null, crossinline content: DIV.(WebContext) -> Unit) {
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
        footer(context, js = js, extraJs = extraJs)
    }
}

