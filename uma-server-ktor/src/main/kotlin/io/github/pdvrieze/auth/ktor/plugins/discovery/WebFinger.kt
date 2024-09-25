package io.github.pdvrieze.auth.ktor.plugins.discovery

import io.ktor.server.application.*
import io.ktor.server.routing.*

fun Route.webFinger() {
    get("/webfinger") {
        val resource: String?
        val rel: String?
        call.request.queryParameters.run {
            resource = get("resource")
            rel = get("rel")
        }


    }
}
