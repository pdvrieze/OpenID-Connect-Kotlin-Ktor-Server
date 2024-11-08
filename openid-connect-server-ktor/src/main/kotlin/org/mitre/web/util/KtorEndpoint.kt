package org.mitre.web.util

import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import org.mitre.util.oidJson

interface KtorEndpoint {
    fun Route.addRoutes()
}

