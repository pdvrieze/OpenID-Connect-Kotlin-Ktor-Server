package org.mitre.oauth2.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.serializer
import org.mitre.util.oidJson

suspend inline fun <reified T> RoutingContext.tokenApiView(
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(serializer<T>(), jsonEntity, code)

suspend fun ApplicationCall.respondJson(
    jsonEntity: JsonElement,
    code:HttpStatusCode = HttpStatusCode.OK,
) = respondText(jsonEntity.toString(), ContentType.Application.Json, code)

suspend inline fun <reified T> ApplicationCall.respondJson(
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) = respondJson(serializer<T>(), jsonEntity, code)

suspend fun <T> ApplicationCall.respondJson(
    serializer: KSerializer<T>,
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) {
    val textData = oidJson.encodeToString(serializer, jsonEntity)
    respondText(textData, ContentType.Application.Json, code)
}
