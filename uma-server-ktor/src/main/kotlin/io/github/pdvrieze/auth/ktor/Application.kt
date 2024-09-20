package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.github.pdvrieze.auth.ktor.plugins.configureSerialization
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.sessions.*
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.util.OpenIdContextPlugin

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    val configuration = OpenIdConfigurator("http://localhost:8080")
    install(Sessions) {
        cookie<OpenIdSessionStorage>(OpenIdSessionStorage.COOKIE_NAME, SessionStorageMemory())
    }
    install(OpenIdContextPlugin) {
        context = configuration.resolveDefault()
    }
    install(Authentication) {
        basic {
            realm = "test-ktor-openid"
            this.validate { credentials ->
                // temporary testing
                if (credentials.name == "admin" && credentials.password == "secret") {
                    UserIdPrincipal("admin")
                } else {
                    null
                }
            }
        }
    }
    configureSerialization()
//    configureTemplating()
//    configureDatabases()
    configureRouting(configuration.resolveDefault())
}
