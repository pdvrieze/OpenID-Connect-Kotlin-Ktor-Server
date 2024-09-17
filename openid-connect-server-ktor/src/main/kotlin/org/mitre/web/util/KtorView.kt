package org.mitre.web.util

import io.ktor.server.application.*
import io.ktor.util.pipeline.*

fun interface KtorView: (suspend PipelineContext<Unit, ApplicationCall>.(Unit) -> Unit) {
    override suspend fun invoke(context: PipelineContext<Unit, ApplicationCall>, subject: Unit) {
        context.invoke()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.invoke()
}
