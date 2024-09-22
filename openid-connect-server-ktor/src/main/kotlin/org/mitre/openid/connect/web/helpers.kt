package org.mitre.openid.connect.web

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.web.util.openIdContext

fun PipelineContext<Unit, ApplicationCall>.clientRegistrationUri(client: OAuthClientDetails) =
    URLBuilder(openIdContext.config.issuer).apply { path("register", client.clientId!!) }.buildString()

fun Route.get(route1: String, route2:String, vararg routes: String, body: suspend PipelineContext<Unit, ApplicationCall>.(Unit) -> Unit) {
    get(route1, body)
    get(route2, body)
    for(route in routes) {
        get(route,body)
    }
}
