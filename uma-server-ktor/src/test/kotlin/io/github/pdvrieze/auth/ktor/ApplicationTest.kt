package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.github.pdvrieze.auth.ktor.plugins.openIdContext
import io.github.pdvrieze.auth.ktor.plugins.wellKnown
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*

class ApplicationTest {
    @Test
    fun testRoot() = testApplication {
        application {
            configureRouting()
        }
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
            assertEquals("Hello World!", bodyAsText())
        }
    }
}

class WebFingerTest {
    @Test
    fun testWellKnown() = testApplication {
        application {
            openIdContext("io.github.pdvrieze") {
                wellKnown {

                }
            }
        }
    }
}
