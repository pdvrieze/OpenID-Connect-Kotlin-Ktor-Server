package org.mitre.web.util

import io.ktor.server.routing.*

interface KtorEndpoint {
    fun Route.addRoutes()
}
