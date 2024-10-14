package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.JsonElement
import org.mitre.oauth2.view.respondJson


suspend fun RoutingContext.jsonApprovedSiteView(
    entity: JsonElement,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(entity, code)

/**
 * @author jricher
 */
object JsonApprovedSiteView {
    const val VIEWNAME: String = "jsonApprovedSiteView"
}
