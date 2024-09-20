package io.github.pdvrieze.auth.ktor.plugins

import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.resources.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.web.util.OpenIdContext

fun Application.configureRouting(configuration: OpenIdContext) {
    install(Resources)
    routing {
        staticResources("/bootstrap2", "bootstrap2")
        staticResources("/css", "css")
        staticResources("/images", "images")
        staticResources("/images", "images")
        staticResources("/js", "js")
        staticResources("/template", "template")


        get("/") {
            call.respondText("Hello World!")
        }
    }
}
