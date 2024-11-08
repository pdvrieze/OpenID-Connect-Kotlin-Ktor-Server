package org.mitre.openid.connect.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer
import org.mitre.util.oidJson

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

suspend inline fun <reified T> RoutingContext.clientEntityViewForUsers(
    jsonEntity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    clientEntitityViewForUsers<T>(serializer<T>(), jsonEntity, code)
}

suspend fun <T> RoutingContext.clientEntitityViewForUsers(
    serializer: KSerializer<T>,
    entity: T,
    code: HttpStatusCode = HttpStatusCode.OK,
) {
    val filtered = when(val jsonElement = oidJson.encodeToJsonElement(serializer, entity)) {
        is JsonArray -> JsonArray(jsonElement.map(::filterObject))
        else -> filterObject(jsonElement)
    }

    call.respondText(filtered.toString(), ContentType.Application.Json, code)
}

private fun filterObject(e: JsonElement) =
    JsonObject(e.jsonObject.filterKeys { it in whitelistedFields })

private val whitelistedFields: Set<String> =
    hashSetOf("clientName", "clientId", "id", "clientDescription", "scope", "logoUri")
