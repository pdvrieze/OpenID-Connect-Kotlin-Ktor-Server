package io.github.pdvrieze.auth.ktor.plugins

import io.github.pdvrieze.openid.web.style.default.DefaultStyles
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.resources.*
import io.ktor.server.routing.*
import org.mitre.openid.connect.web.RootController

fun Application.configureRouting(additional: Route.() -> Unit = {}) {
    install(Resources)
    routing {
        get("/resources/bootstrap2/css/bootstrap.css") { call.respondCss { with(DefaultStyles) { bootstrap() } }}
        get("/resources/bootstrap2/css/bootstrap-responsive.css") { call.respondCss { with(DefaultStyles) { bootstrapResponsive() } }}

        staticResources("/resources/bootstrap2", "bootstrap2")
        staticResources("/resources/css", "css")
        staticResources("/resources/images", "images")
        staticResources("/resources/images", "images")
        staticResources("/resources/js", "js")
        staticResources("/resources/template", "template")


        with(RootController) { addRoutes() }


        additional()
    }
}
