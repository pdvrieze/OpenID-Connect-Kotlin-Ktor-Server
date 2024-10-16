package io.github.pdvrieze.auth.ktor

import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.testing.*
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.OpenIdContextPlugin
import kotlin.test.assertEquals

abstract class ApiTest private constructor(endpoints: Array<out KtorEndpoint>, private val includeAuthzFilter: Boolean) {

    constructor(vararg endpoints: KtorEndpoint) : this(endpoints, false)
    constructor(includeAuthzFilter: Boolean = false, vararg endpoints: KtorEndpoint) : this(endpoints, includeAuthzFilter)

    protected lateinit var testContext: TestContext

    private val endpoints = endpoints.toList()

    protected open val deletableTables: List<Table> = emptyList()

    @Before
    open fun setUp() {
        val configurator = OpenIdConfigurator("https://example.com/")
        testContext = TestContext(configurator)
        transaction(configurator.database) {
            for (table in deletableTables) {
                table.deleteAll()
            }
        }
    }


    protected open fun configureApplication(testBuilder: ApplicationTestBuilder) {
        testBuilder.application {
            this.install(OpenIdContextPlugin) { this.context = this@ApiTest.testContext }
            this.authentication {
                this.basic {
                    this.validate { cred ->
                        when (cred.name) {
                            "admin" -> UserIdPrincipal(cred.name).takeIf { cred.password == "secret" }
                            "user" -> UserIdPrincipal(cred.name).takeIf { cred.password == "userSecret" }
                            "client" -> UserIdPrincipal(cred.name).takeIf { cred.password == "clientSecret" }
                            else -> null
                        }
                    }
                }
            }

            this.configureRouting() {
                for (endpoint in this@ApiTest.endpoints) {
                    with(endpoint) { addRoutes() }
                }
            }
        }
    }

    protected fun testEndpoint(block: suspend ApplicationTestBuilder.() -> Unit) {
        testApplication {
            configureApplication(this)
            block()
        }
    }

    suspend fun ApplicationTestBuilder.getUnAuth(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val r = client.get(url, block)
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.status}")

        return r
    }

    suspend fun ApplicationTestBuilder.getUser(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return getUnAuth(url, statusCode, client) {
            basicAuth("user", "userSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.getClient(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return getUnAuth(url, statusCode, client) {
            basicAuth("client", "clientSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.getAdmin(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return getUnAuth(url, statusCode, client) {
            basicAuth("admin", "secret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.putUnAuth(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val r = client.put(url, block)
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.status}")

        return r
    }

    suspend fun ApplicationTestBuilder.putUser(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return putUnAuth(url, statusCode, client) {
            basicAuth("user", "userSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.putClient(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return putUnAuth(url, statusCode, client) {
            basicAuth("client", "clientSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.putAdmin(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return putUnAuth(url, statusCode, client) {
            basicAuth("admin", "secret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.postUnAuth(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val r = client.post(url, block)
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.status}")

        return r
    }

    suspend fun ApplicationTestBuilder.postUser(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return postUnAuth(url, statusCode, client) {
            basicAuth("user", "userSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.postClient(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return postUnAuth(url, statusCode, client) {
            basicAuth("client", "clientSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.postAdmin(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return postUnAuth(url, statusCode, client) {
            basicAuth("admin", "secret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.deleteUnAuth(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.NoContent,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val r = client.delete(url, block)
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.status}")

        return r
    }

    suspend fun ApplicationTestBuilder.deleteUser(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.NoContent,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return deleteUnAuth(url, statusCode, client) {
            basicAuth("user", "userSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.deleteClient(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.NoContent,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return deleteUnAuth(url, statusCode, client) {
            basicAuth("client", "clientSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.deleteAdmin(
        url: String,
        statusCode: HttpStatusCode = HttpStatusCode.NoContent,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return deleteUnAuth(url, statusCode, client) {
            basicAuth("admin", "secret")
            block()
        }
    }

    class TestContext(configurator: OpenIdConfigurator): OpenIdConfigurator.DefaultContext(configurator) {
        override fun resolveAuthServiceAuthorities(name: String): Collection<GrantedAuthority> {
            return when (name) {
                "admin" -> listOf(GrantedAuthority.ROLE_ADMIN, GrantedAuthority.ROLE_USER, GrantedAuthority.ROLE_CLIENT)
                "client" -> listOf(GrantedAuthority.ROLE_CLIENT)
                "user" -> listOf(GrantedAuthority.ROLE_USER)
                else -> emptyList()
            }
        }
    }
}
