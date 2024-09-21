package io.github.pdvrieze.openid.web.views

import io.github.pdvrieze.openid.web.WebContext
import kotlinx.html.HTML
import kotlinx.html.b
import kotlinx.html.blockQuote
import kotlinx.html.div
import kotlinx.html.h1
import kotlinx.html.p
import kotlinx.html.span
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.exception.OAuth2Exception

fun HTML.error(
    context: WebContext,
) = error(context, OAuthErrorCodes.SERVER_ERROR, "See the logs for details")

fun HTML.error(
    context: WebContext,
    error: OAuth2Exception
) = error(context, error.oauth2ErrorCode, error.message ?: error.javaClass.simpleName)

fun HTML.error(
    context: WebContext,
    errorCode: OAuthErrorCodes,
    errorMessage: String,
) = error(context, errorCode.code, errorMessage)

fun HTML.error(
    context: WebContext,
    errorCodeString: String,
    errorMessage: String,
) {

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

