package io.github.pdvrieze.auth.ktor

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import io.github.pdvrieze.auth.ktor.plugins.OpenIdConfigurator
import io.github.pdvrieze.auth.ktor.plugins.configureRouting
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.sessions.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.Before
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.service.ClientLoadingResult
import org.mitre.openid.connect.view.OAuthError
import org.mitre.web.OpenIdSessionStorage
import org.mitre.web.util.KtorEndpoint
import org.mitre.web.util.OpenIdContextPlugin
import org.mitre.web.util.openIdContext
import kotlin.test.assertEquals

abstract class ApiTest private constructor(endpoints: Array<out KtorEndpoint>, private val includeAuthzFilter: Boolean) {

    constructor(vararg endpoints: KtorEndpoint) : this(endpoints, false)
    constructor(includeAuthzFilter: Boolean = false, vararg endpoints: KtorEndpoint) : this(endpoints, includeAuthzFilter)

    protected lateinit var testContext: TestContext
    lateinit var clientSecret: String

    private val endpoints = endpoints.toList()

    protected open val deletableTables: List<Table> = emptyList()

    @Before
    open fun setUp() {
        val configurator = OpenIdConfigurator("https://example.com/")
        val key = JWK.parse(SIGNING_KEY)
        configurator.signingKeySet = mapOf(key.keyID to key)

        testContext = TestContext(configurator)
        transaction(configurator.database) {
            for (table in deletableTables) {
                table.deleteAll()
            }
        }
    }


    protected open fun configureApplication(testBuilder: ApplicationTestBuilder) {
        testBuilder.client.config {
            install(ContentNegotiation) {
                json(Json { prettyPrint = true })
            }
        }
        testBuilder.application {
            install(Sessions) {
                cookie<OpenIdSessionStorage>(OpenIdSessionStorage.COOKIE_NAME, SessionStorageMemory())
            }
            install(OpenIdContextPlugin) { this.context = this@ApiTest.testContext }
            authentication {
                this.basic {
                    this.validate { cred ->
                        when (cred.name) {
                            "admin" -> UserIdPrincipal(cred.name).takeIf { cred.password == "secret" }
                            "user" -> UserIdPrincipal(cred.name).takeIf { cred.password == "userSecret" }
                            "MyClient" -> UserIdPrincipal(cred.name).takeIf {
                                openIdContext.clientDetailsService.loadClientAuthenticated(cred.name, cred.password) is ClientLoadingResult.Found
                            }
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
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.getStatusErrorDetails()}")

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
            basicAuth("MyClient", clientSecret)
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
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.getStatusErrorDetails()}")

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
            basicAuth("MyClient", clientSecret)
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
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.getStatusErrorDetails()}")

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
            basicAuth("MyClient", clientSecret)
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

    suspend fun ApplicationTestBuilder.submitUnAuth(
        url: String,
        formParameters: Parameters,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        val r = client.submitForm(url, formParameters, false, block)
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.getStatusErrorDetails()}")

        return r
    }

    suspend fun ApplicationTestBuilder.submitUser(
        url: String,
        formParameters: Parameters,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return submitUnAuth(url, formParameters, statusCode, client) {
            basicAuth("user", "userSecret")
            block()
        }
    }

    suspend fun ApplicationTestBuilder.submitClient(
        url: String,
        formParameters: Parameters,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return submitUnAuth(url, formParameters, statusCode, client) {
            basicAuth("MyClient", clientSecret)
            block()
        }
    }

    suspend fun ApplicationTestBuilder.submitAdmin(
        url: String,
        formParameters: Parameters,
        statusCode: HttpStatusCode = HttpStatusCode.OK,
        client: HttpClient = this.client,
        block: HttpRequestBuilder.() -> Unit = {},
    ): HttpResponse {
        return submitUnAuth(url, formParameters, statusCode, client) {
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
        assertEquals(statusCode, r.status, "Unexpected response status: ${r.getStatusErrorDetails()}")

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
            basicAuth("MyClient", clientSecret)
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

    suspend fun HttpResponse.getStatusErrorDetails() = buildString {
        append(status)
        if (!status.isSuccess() && contentType() == ContentType.Application.Json) {
            val body = bodyAsText()
            val error = runCatching { Json.decodeFromString<OAuthError>(body).toString() }.getOrDefault(body)
            if (error.isNotBlank()) {
                append(' ').append(error)
            }
        }
    }

    class TestContext(configurator: OpenIdConfigurator): OpenIdConfigurator.DefaultContext(configurator) {
        override fun resolveAuthServiceAuthorities(name: String): Collection<GrantedAuthority> {
            return when (name) {
                "admin" -> listOf(GrantedAuthority.ROLE_ADMIN, GrantedAuthority.ROLE_USER, GrantedAuthority.ROLE_CLIENT)
                "MyClient" -> listOf(GrantedAuthority.ROLE_CLIENT)
                "user" -> listOf(GrantedAuthority.ROLE_USER)
                else -> emptyList()
            }
        }
    }

    companion object {
        val SIGNING_KEY: String = """|{
            |    "p": "_ZMsTanYI15KZjlZUcYR7MSDKY7c_b12WzS6qQ4Q1w90qBunvn2_elNwyY7XMxXIFG5psINOoGFwFaGmeFois27lDilD6puE6OcGulSXFxj8t3uVEJCLTOo9_OhgwDqhhE9tpJsLIByOYwIJngweSKmrn5c6DQS9iTZ39tARPi0",
            |    "kty": "RSA",
            |    "q": "jOK2lCEeNdb7KLUlZINxEGOHIryJ2ZSZ4K5hM-83GOVnFXQHP1eRqeqxZjgm18PTw3WgPWCCSdE0yMudbdwJP5Z2x_JBRjAW8o3eX7MxIDeHjYpfqdm36_U_bzRD6AyfCRZ3xcqkgOk_dHueIHdyxrX7ZMrcPio3pnJ_9Tz2Kr8",
            |    "d": "AQy9lU06fLNHKdPtHqUCclUCZV4ZatxCHJqfz9VU8adORAnX8oU9hYx3dE79bLGiF1nZjigMYppgzwJQFrPx7T2RSkQg_A8j1sk31MotqwssK75zyUqzUQc8yH2hqoldt8E6wYm7ZwyiPT398ldzIWzCFFbk5RpVZeU-Bouxi8lmiED_S_09VJAHL-8nYMZomRZSZG_md1r763SFCRRcmeyRuefnA7kJM8SpSw1zDUvTsmnVfNqf2XfwviGFOFbwlPqHHmCfLv8lCafPIxbL5tzFn5K3c94kDethh0u-ywgsK0ogfpbJhraeHAlsY8qNocHUFsGPI8TbCvjxPORviQ",
            |    "e": "AQAB",
            |    "use": "sig",
            |    "kid": "uqDUJ0zzEnqqSR35iQDVLDHlj-SMcEW6y3KRbTiK55o",
            |    "qi": "X7NvKdXqixK7tlU-52a8UWl9VqH_-GZGf6G8i4PJbROmEmY5iaiwlX7veTibElglUB2E-IA92if7fXMe7uZMTeE5gHvWh-cYi72F_M7ZsdxhB5qJNAX5rQMkXBsCYumy2ABp_s7HSvn0n7AbHumlZ9Ntht8iWHmqxB2nETBKkAc",
            |    "dp": "ccb9lANnhccjHucQms6C8HfkWltN8VR3rMjmEEDNcZHvyBZQl_qYVezmqKm9CaD2W6SHK7pfJztRLYOQzGO1OknB4S7G2JfbdR1kOWsHOEfv7Ow4oGwa9PINylMCRn6IRnPVQIyI22m0wdwCMLZDSFtJNJyIYZsE6HJWNZp6gik",
            |    "alg": "RS256",
            |    "dq": "d1mMMHrJ2_RuOrMSpU7QloCqN1wfL4q6vOMdB2EMfPPB2yO7DAcEKDzg4eaJyVlk6P2ZrMU4Oo6XN89-Y1X3I740i_gHIg2VMw_KJapo4JEKLXbeycXeEG9nuK4_JLKke49kEdQ0fdya2_PpJjnqqrn56Q4NfEBJeqEfE0L8i4M",
            |    "n": "i40NAPDU3RZCAJDZWeaaZohtPgzevuxA1lJCtELewlYoKZktXZDl7Uzafu65vAFyOyqIDUuTSqbmPNFRA6cDNkK992PUepzEPtx9qthBBiYEoUwWtwkkui-sxpON2RJOePZmLOkfCuxq57bhiUsFIKf8am_Dw101mo49Keo9AQRNhscgnhB6VrDq0qGqTpf0ESaWbMlzwObV0a6NVT5susnnWXyUvwO7P57X30OtxMZrfPrRr_KDbkA9fX_MLOhnS4Rj0aYyJ7ClWUtKRQV8M0Sm0z56VD39MDPrKklP4wPm889-gFCpl0Y4ajMhSWD811LQwn0OFHj7pM59XE7Fkw"
            |}""".trimMargin()

        val JWT_VERIFIER = RSASSAVerifier(JWK.parse(SIGNING_KEY).toPublicJWK() as RSAKey)

    }
}