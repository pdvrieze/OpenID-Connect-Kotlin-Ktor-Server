package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.view.respondJson

suspend fun PipelineContext<Unit, ApplicationCall>.jsonErrorView(
    errorTitle: String,
    errorMessage: String,
    code: HttpStatusCode = HttpStatusCode.InternalServerError,
) = call.respondJson(
    buildJsonObject {
        put("error", errorTitle)
        put("error_description", errorMessage)
    },
    code
)

/**
 * @author aanganes, jricher
 */
object JsonErrorView {
    const val ERROR_MESSAGE: String = "errorMessage"
    const val ERROR: String = "error"
    const val VIEWNAME: String = "jsonErrorView"
}
