package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer

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

    const val VIEWNAME: String = "clientEntityViewUsers"
}

suspend inline fun <reified T> PipelineContext<Unit, ApplicationCall>.clientEntityViewForUsers(
    jsonEntity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    clientEntitityViewForUsers<T>(serializer<T>(), jsonEntity, code)
}

suspend fun <T> PipelineContext<Unit, ApplicationCall>.clientEntitityViewForUsers(
    serializer: KSerializer<T>,
    entity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    val jsonObj = Json.encodeToJsonElement(serializer, entity).jsonObject
    val filtered = JsonObject(jsonObj.filterKeys { it in whitelistedFields })

    call.respondText(filtered.toString(), ContentType.Application.Json, code)
}

private val whitelistedFields: Set<String> =
    hashSetOf("clientName", "clientId", "id", "clientDescription", "scope", "logoUri")
