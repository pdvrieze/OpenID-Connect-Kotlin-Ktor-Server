package org.mitre.web.util

import io.ktor.server.routing.*
import kotlinx.serialization.json.Json

interface KtorEndpoint {
    val json get() = Json.Default
    fun Route.addRoutes()
}

