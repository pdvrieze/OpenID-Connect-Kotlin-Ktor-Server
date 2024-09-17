package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.view.respondJson


suspend fun PipelineContext<Unit, ApplicationCall>.jsonApprovedSiteView(
    entity: JsonElement,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(entity, code)

/**
 * @author jricher
 */
object JsonApprovedSiteView {
    const val VIEWNAME: String = "jsonApprovedSiteView"
}
