package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.tags.formattedPage
import io.github.pdvrieze.openid.web.tags.sidebar
import io.github.pdvrieze.openid.web.tags.topBar
import kotlinx.html.DIV
import kotlinx.html.TagConsumer
import kotlinx.html.div

inline fun <T, C : TagConsumer<T>> C.baseView(context: WebContext, title: String, pageName: String, hasSideBar: Boolean = false, extraJs: String? = null, crossinline content: DIV.(WebContext) -> Unit): T {
    return formattedPage(context, title, extraJs) {
        topBar(context, pageName)
        div("container-fluid main") {
            div("row-fluid") {
                if(hasSideBar) sidebar(context)
                content(context)
            }
        }
    }
}
