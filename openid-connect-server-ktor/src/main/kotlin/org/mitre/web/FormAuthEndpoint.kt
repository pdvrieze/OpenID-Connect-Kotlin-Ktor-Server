package org.mitre.web

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.openIdContext
import org.mitre.web.util.update
import java.net.URI
import java.util.*

object FormAuthEndpoint: KtorEndpoint {
    override fun Route.addRoutes() {
        get("login") { showLoginRequest() }
        post("login") { doLogin() }
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.showLoginRequest() {
        return htmlLoginView(null, null, call.request.queryParameters["redirect_uri"])
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.doLogin() {
        val formParams = call.receiveParameters()

        val userName = formParams["username"]
        val password = formParams["password"]

        if (!userName.isNullOrBlank() && !password.isNullOrBlank() &&
            openIdContext.checkCredential(UserPasswordCredential(userName, password))) {

            val principal = UserIdPrincipal(userName)
            call.authentication.principal(principal)
            call.sessions.update<OpenIdSessionStorage> { it?.copy(principal = principal) ?: OpenIdSessionStorage(principal = principal) }
            val redirect = formParams["redirect"]?.takeIf { ! URI.create(it).isAbsolute } ?: "/"
            return call.respondRedirect(redirect)
        }

        val locales = call.request.acceptLanguageItems().map { Locale(it.value) }
        val error = openIdContext.messageSource.resolveCode("login.error", locales)?.format(null)
        call.response.status(HttpStatusCode.Unauthorized)
        return htmlLoginView(formParams["username"], error, formParams["redirect"], HttpStatusCode.Unauthorized)
    }

}
