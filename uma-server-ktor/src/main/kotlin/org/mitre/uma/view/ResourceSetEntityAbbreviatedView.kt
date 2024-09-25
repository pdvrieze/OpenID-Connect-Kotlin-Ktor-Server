package org.mitre.uma.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.mitre.oauth2.view.respondJson
import org.mitre.openid.connect.view.JsonEntityView
import org.mitre.uma.model.ResourceSet
import org.mitre.util.getLogger
import org.mitre.web.util.config

suspend fun PipelineContext<Unit, ApplicationCall>.resourceSetEntityAbbreviatedView(
    rs: ResourceSet,
    location: String? = null,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    if (location != null) {
        call.response.header(HttpHeaders.Location, location)
    }

    call.respondJson(buildJsonObject {
        put("_id", rs.id.toString())
        put("user_access_policy_uri", "${config.safeIssuer}manage/user/policy/${rs.id}")
    }, code)

}

class ResourceSetEntityAbbreviatedView {

    companion object {
        private val logger = getLogger<JsonEntityView>()

        const val VIEWNAME: String = "resourceSetEntityAbbreviatedView"

        const val LOCATION: String = "location"
    }
}
