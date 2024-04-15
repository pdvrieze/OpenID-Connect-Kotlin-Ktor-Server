package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.configureDatabases
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.github.pdvrieze.auth.ktor.plugins.configureSerialization
import io.github.pdvrieze.auth.ktor.plugins.configureTemplating
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    configureSerialization()
    configureTemplating()
    configureDatabases()
    configureRouting()
}
