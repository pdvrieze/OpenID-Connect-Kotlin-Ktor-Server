package org.mitre.discovery.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.mitre.openid.connect.service.MITREidDataService
import org.mitre.util.getLogger
import java.io.IOException

suspend fun PipelineContext<Unit, ApplicationCall>.webfingerView(
    resource: String,
    issuer: String,
    code: HttpStatusCode = HttpStatusCode.OK,
) = with(WebfingerViews) { webfingerView(resource, issuer, code) }

object WebfingerViews {

    suspend fun PipelineContext<Unit, ApplicationCall>.webfingerView(
        resource: String,
        issuer: String,
        code: HttpStatusCode = HttpStatusCode.OK,
    ) {
        try {
            val obj = buildJsonObject {
                put("subject", resource)
                putJsonArray("links") {
                    addJsonObject {
                        put("rel", "http://openid.net/specs/connect/1.0/issuer")
                        put("href", issuer)
                    }
                }
            }
            call.respondText(MITREidDataService.json.encodeToString(obj), CT_JRD, code)
        } catch (e: IOException) {
            logger.error("IOException in JsonEntityView.java: ", e)
            throw e
        }
    }

    val CT_JRD = ContentType("application", "jrd+json")

    private val logger = getLogger<WebfingerViews>()

}
