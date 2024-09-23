package io.github.pdvrieze.openid.web.tags

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.FlowOrPhrasingContent
import kotlinx.html.HtmlBlockInlineTag
import kotlinx.html.HtmlTagMarker
import kotlinx.html.img
import kotlinx.html.span
import kotlinx.html.title

@HtmlTagMarker
fun HtmlBlockInlineTag.copyright(context: WebContext) {
    if (context.config.isHeartMode) {
        span("pull-left") {
            img(src="resources/images/heart_mode.png", alt="HEART Mode"){ title="This server is running in HEART Compliance Mode" }
        }
    }
    with (context.intl) { message("copyright", context.config.projectVersion)}
}
