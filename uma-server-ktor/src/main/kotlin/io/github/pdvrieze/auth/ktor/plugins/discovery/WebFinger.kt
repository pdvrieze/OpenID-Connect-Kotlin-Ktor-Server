package io.github.pdvrieze.auth.ktor.plugins.discovery

import io.github.pdvrieze.auth.ktor.plugins.WellKnown
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonObject

fun WellKnown.webFinger() {
    routing {
        get("/webfinger") {
            val resource: String?
            val rel: String?
            call.request.queryParameters.run {
                resource = get("resource")
                rel = get("rel")
            }


        }
    }
}
