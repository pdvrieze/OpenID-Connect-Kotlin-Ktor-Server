import io.github.pdvrieze.openid.web.WebContext
import io.github.pdvrieze.openid.web.views.baseView
import kotlinx.html.TagConsumer
import kotlinx.html.div
import kotlinx.html.h2
import kotlinx.html.p

// comment("TODO: highlight proper section of topbar; what is the right way to do this?")
fun <T, C : TagConsumer<T>> C.contact(context: WebContext): T {
    val title = context.intl.messageText("contact.title")
    return baseView(context, title, "Contact", true) {
        with(context.intl) {
            div(classes = "span10") {
                div(classes = "hero-unit") {
                    h2() { message("contact.title") }
                    p() { message("contact.body") }
                }
            }
        }
    }
}
