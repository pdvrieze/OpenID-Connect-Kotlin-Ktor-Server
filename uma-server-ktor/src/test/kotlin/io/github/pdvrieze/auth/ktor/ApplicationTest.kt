package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*

class ApplicationTest {
    @Test
    fun testRoot() = testApplication {
        val configurator = OpenIdConfigurator("http://localhost:8080")
        application {
            configureRouting(configurator.resolveDefault())
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
        val configurator = OpenIdConfigurator("http://localhost:8080")
        application {
            configureRouting(configurator.resolveDefault())
        }
    }
}
