package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.view.respondJson

suspend fun PipelineContext<Unit, ApplicationCall>.jsonEntityView(
    entity: JsonElement,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(entity, code)

/**
 * @author jricher
 */
object JsonEntityView {
    const val ENTITY: String = "entity"
    const val VIEWNAME: String = "jsonEntityView"
}
