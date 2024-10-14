package org.mitre.openid.connect.ktor.views

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

suspend fun RoutingContext.jwkView(keys: Map<String, JWK>) {
    val jwkSet = JWKSet(ArrayList(keys.values))
    call.respondText(jwkSet.toString(), ContentType.Application.Json)
}
