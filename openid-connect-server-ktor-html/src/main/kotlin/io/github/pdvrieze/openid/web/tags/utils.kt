package io.github.pdvrieze.openid.web.tags

import kotlinx.html.*

@HtmlTagMarker
internal inline fun FlowOrInteractiveOrPhrasingContent.a_data(
    href: String? = null,
    dataToggle: String? = "collapse",
    dataTarget: String? = ".nav-collapse",
    target: String? = null,
    classes: String? = null,
    crossinline block: A.() -> Unit = {},
): Unit {
    A(attributesMapOf("href", href, "target", target, "class", classes, "data-toggle", dataToggle, "data-target", dataTarget), consumer).visit(block)
}

