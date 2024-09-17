package org.mitre.oauth2.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

suspend inline fun <reified T> PipelineContext<Unit, ApplicationCall>.tokenApiView(
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) = call.respondJson(serializer<T>(), jsonEntity, code)

suspend inline fun <reified T> ApplicationCall.respondJson(
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) = respondJson(serializer<T>(), jsonEntity, code)

suspend fun <T> ApplicationCall.respondJson(
    serializer: KSerializer<T>,
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) {
    val textData = Json.encodeToString(serializer, jsonEntity)
    respondText(textData, ContentType.Application.Json, code)
}
