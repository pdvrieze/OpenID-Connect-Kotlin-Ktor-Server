package org.mitre.oauth2.view

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

inline suspend fun <reified T> PipelineContext<Unit, ApplicationCall>.tokenApiView(
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) = tokenApiView(serializer<T>(), jsonEntity, code)

suspend fun <T> PipelineContext<Unit, ApplicationCall>.tokenApiView(
    serializer: KSerializer<T>,
    jsonEntity: T,
    code:HttpStatusCode = HttpStatusCode.OK,
) {
    val textData = Json.encodeToString(serializer, jsonEntity)
    call.respondText(textData, ContentType.Application.Json, code)
}
