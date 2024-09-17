package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.serializer
import org.mitre.oauth2.view.respondJson

/**
 *
 * View bean for field-limited view of client entity, for regular users.
 *
 * @see AbstractClientEntityView
 *
 * @see ClientEntityViewForAdmins
 *
 * @author jricher
 */
object ClientEntityViewForUsers {
    private val whitelistedFields: Set<String> =
        hashSetOf("clientName", "clientId", "id", "clientDescription", "scope", "logoUri")

    const val VIEWNAME: String = "clientEntityViewUsers"
}
suspend inline fun <reified T> PipelineContext<Unit, ApplicationCall>.clientEntityViewForUsers(
    jsonEntity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(serializer<T>(), jsonEntity, code)
