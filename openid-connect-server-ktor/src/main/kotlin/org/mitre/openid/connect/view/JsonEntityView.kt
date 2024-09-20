package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.view.respondJson

suspend fun PipelineContext<Unit, ApplicationCall>.jsonEntityView(
    entity: JsonElement,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(entity, code)

suspend fun PipelineContext<Unit, ApplicationCall>.jsonEntityView(
    dummy: Nothing? = null,
    active: Boolean,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(buildJsonObject { put("active", active) }, code)

/**
 * @author jricher
 */
object JsonEntityView {
    const val ENTITY: String = "entity"
    const val VIEWNAME: String = "jsonEntityView"
}
