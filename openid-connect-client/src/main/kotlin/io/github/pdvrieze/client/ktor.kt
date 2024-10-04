package io.github.pdvrieze.client

import io.ktor.client.statement.*
import io.ktor.http.*

suspend fun HttpResponse.onError(action: suspend (HttpStatusCode) -> Nothing): HttpResponse = apply {
    if (!this.status.isSuccess()) action(this.status)
}
