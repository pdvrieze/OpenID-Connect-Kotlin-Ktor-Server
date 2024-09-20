package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.TagConsumer
import kotlinx.html.b
import kotlinx.html.blockQuote
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.p
import kotlinx.html.span
import org.mitre.oauth2.exception.ErrorCodes
import org.mitre.oauth2.exception.OAuth2Exception

fun <T, C : TagConsumer<T>> C.error(
    context: WebContext,
): T = error(context, ErrorCodes.SERVER_ERROR, "See the logs for details")

fun <T, C : TagConsumer<T>> C.error(
    context: WebContext,
    error: OAuth2Exception
): T = error(context, error.oauth2ErrorCode, error.message ?: error.javaClass.simpleName)

fun <T, C : TagConsumer<T>> C.error(
    context: WebContext,
    errorCode: ErrorCodes,
    errorMessage: String,
): T = error(context, errorCode.code, errorMessage)

fun <T, C : TagConsumer<T>> C.error(
    context: WebContext,
    errorCodeString: String,
    errorMessage: String,
): T {

    val title = context.intl.messageText("error.title")
    return baseView(context, title, "Error", false) {
        with(context.intl) {
            div(classes="offset1 span10") {
                div(classes="hero-unit") {
                    h1() {span() {message("error.header",  )}
                        span(classes="text-error") { +errorCodeString }
                    }
                    p() {
                        message("error.message",  )
                        blockQuote(classes="text-error") {b() { +errorMessage }}
                    }

                }

            }
        }
    }
}

