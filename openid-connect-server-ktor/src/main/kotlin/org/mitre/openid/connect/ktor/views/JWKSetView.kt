package org.mitre.openid.connect.ktor.views

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import org.mitre.web.util.CT_JSON

suspend fun PipelineContext<Unit, ApplicationCall>.jwkView(keys: Map<String, JWK>) {
    val jwkSet = JWKSet(ArrayList(keys.values))
    call.respondText(jwkSet.toString(), CT_JSON)
}
