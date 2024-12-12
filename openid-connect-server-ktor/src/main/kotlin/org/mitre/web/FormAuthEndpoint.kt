package org.mitre.web

import io.github.pdvrieze.auth.AuthFactor
import io.github.pdvrieze.auth.DirectUserAuthentication
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import org.mitre.oauth2.exception.OAuthErrorCodes
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.openid.connect.filter.PlainAuthorizationRequestEndpoint
import org.mitre.openid.connect.view.jsonErrorView
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.config
import org.mitre.web.util.openIdContext
import java.net.URI
import java.time.Instant
import java.util.*

object FormAuthEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        get("login") { showLoginRequest() }
        post("login") { doLogin() }
    }

    suspend fun RoutingContext.showLoginRequest(loginActionUrl: String = config.issuerUrl("login")) {
        return htmlLoginView(loginActionUrl, null, null, call.request.queryParameters["redirect_uri"])
    }

    suspend fun RoutingContext.doLogin(loginActionUrl: String = config.issuerUrl("login")) {
        val formParams = call.receiveParameters()

        val userName = formParams["username"]
        val password = formParams["password"]

        if (!userName.isNullOrBlank() && !password.isNullOrBlank() &&
            openIdContext.checkCredential(UserPasswordCredential(userName, password))) {

            val oldSession = call.sessions.get<OpenIdSessionStorage>()
            val newFactors = (oldSession?.principal as? DirectUserAuthentication)
                ?.authMethods
                ?.let { it + listOf(AuthFactor.PASSWORD) } ?: listOf(AuthFactor.PASSWORD)

            val principal = DirectUserAuthentication(userName, Instant.now(), newFactors)
            call.sessions.set(OpenIdSessionStorage(principal = principal))

            when(val authorizationRequest = oldSession?.authorizationRequest) {
                null -> {
                    call.authentication.principal(principal)
                    return call.respondRedirect(formParams["redirect"]?.takeIf { ! URI.create(it).isAbsolute } ?: "/")
                }

                else -> with (PlainAuthorizationRequestEndpoint) {
                    val redirect = oldSession.redirectUri ?: return jsonErrorView(OAuthErrorCodes.SERVER_ERROR)
                    return respondWithAuthCode(authorizationRequest, principal, redirect, oldSession.state)
                }
            }
        }

        val locales = call.request.acceptLanguageItems().map { Locale(it.value) }
        val error = openIdContext.messageSource.resolveCode("login.error", locales)?.format(null)

        return htmlLoginView(loginActionUrl, formParams["username"], error, formParams["redirect"], HttpStatusCode.Unauthorized)
    }

}
