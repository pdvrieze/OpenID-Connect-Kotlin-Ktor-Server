package org.mitre.openid.connect.web

import io.ktor.http.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import org.mitre.oauth2.model.OAuthClientDetails
import org.mitre.web.util.openIdContext

fun RoutingContext.clientRegistrationUri(client: OAuthClientDetails) =
    URLBuilder(openIdContext.config.issuer).apply { path("register", client.clientId!!) }.buildString()

fun Route.get(route1: String, route2:String, vararg routes: String, body: RoutingHandler) {
    get(route1, body)
    get(route2, body)
    for(route in routes) {
        get(route,body)
    }
}


/**
 * Copied from ktor content negotiation
 */
fun RoutingContext.getSortedAcceptHeader() =
    parseHeaderValue(call.request.accept())
        .map { ContentTypeWithQuality(ContentType.parse(it.value), it.quality) }
        .sortedWith(
            compareByDescending<ContentTypeWithQuality> { it.quality }.thenBy {
                val contentType = it.contentType
                var asterisks = 0
                if (contentType.contentType == "*") {
                    asterisks += 2
                }
                if (contentType.contentSubtype == "*") {
                    asterisks++
                }
                asterisks
            }.thenByDescending { it.contentType.parameters.size }
        )

