package org.mitre.web.util

import io.ktor.server.application.*
import io.ktor.server.sessions.*
import io.ktor.util.pipeline.*

fun interface KtorView: (suspend PipelineContext<Unit, ApplicationCall>.(Unit) -> Unit) {
    override suspend fun invoke(context: PipelineContext<Unit, ApplicationCall>, subject: Unit) {
        context.invoke()
    }

    suspend fun PipelineContext<Unit, ApplicationCall>.invoke()
}

interface WebViews {

}

public inline fun <reified T : kotlin.Any> CurrentSession.update(
    updater: (T?) -> T
): T {
    return updater(get<T>()).also { set<T>(it) }
}
