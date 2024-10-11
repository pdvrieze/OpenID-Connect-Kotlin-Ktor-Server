package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.github.pdvrieze.auth.ktor.plugins.configureSerialization
import io.github.pdvrieze.auth.ktor.plugins.redirectingForm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.util.OpenIdContextPlugin
import org.mitre.web.util.openIdContext

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    val configuration = OpenIdConfigurator("http://localhost:8080") { cred ->
        cred is UserPasswordCredential && when(cred.name) {
            "admin" -> cred.password == "secret"
            else -> false
        }
    }

    install(IgnoreTrailingSlash)
    install(Sessions) {
        cookie<OpenIdSessionStorage>(OpenIdSessionStorage.COOKIE_NAME, SessionStorageMemory())
    }
    install(OpenIdContextPlugin) {
        context = configuration.resolveDefault()
    }
    install(Authentication) {
/*
        basic("basic") {
            realm = "test-ktor-openid"
            validate { credentials ->
                // temporary testing
                if (credentials.name == "admin" && credentials.password == "secret") {
                    UserIdPrincipal("admin")
                } else {
                    null
                }
            }
        }
*/
        session<OpenIdSessionStorage> {
            validate { session ->
                session.principal
            }
            challenge { session ->
                commonChallenge(call)
            }
        }
        redirectingForm("form") {
            userParamName = "username"
            passwordParamName = "password"
            validate { credentials ->
                // temporary testing
                if (credentials.name == "admin" && credentials.password == "secret") {
                    UserIdPrincipal("admin")
                } else {
                    null
                }
            }
            challenge {
                commonChallenge(call)
            }
        }
    }
    configureSerialization()
//    configureTemplating()
//    configureDatabases()
    configureRouting()
}

private suspend fun commonChallenge(call: ApplicationCall) {
    if (call.request.accept()?.contains("text/html") == true) {
        val r = "${call.openIdContext.config.safeIssuer}login?redirect_uri=${call.request.uri}"
        call.respondRedirect(r)
    } else {
        call.respond(HttpStatusCode.Unauthorized)
    }
}
