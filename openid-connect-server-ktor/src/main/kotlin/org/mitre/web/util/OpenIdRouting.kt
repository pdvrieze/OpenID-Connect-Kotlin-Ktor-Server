package org.mitre.web.util

import io.ktor.server.routing.*

class OpenIdRouting(
    routing: Routing,
    val context: OpenIdContext,
) : Route(routing.parent, routing.selector, routing.developmentMode, routing.environment) {

}

