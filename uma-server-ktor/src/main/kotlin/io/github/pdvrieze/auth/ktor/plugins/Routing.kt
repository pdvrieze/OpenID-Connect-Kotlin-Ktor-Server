package io.github.pdvrieze.auth.ktor.plugins

import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.resources.*
import io.ktor.server.routing.*

fun Application.configureRouting(additional: Route.() -> Unit = {}) {
    install(Resources)
    routing {
        staticResources("/bootstrap2", "bootstrap2")
        staticResources("/css", "css")
        staticResources("/images", "images")
        staticResources("/images", "images")
        staticResources("/js", "js")
        staticResources("/template", "template")
/*

        get("/") {
            call.respondText("Hello World!")
        }
*/

        additional()
    }
}
