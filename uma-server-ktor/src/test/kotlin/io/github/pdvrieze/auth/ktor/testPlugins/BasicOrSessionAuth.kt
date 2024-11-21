package io.github.pdvrieze.auth.ktor.testPlugins

import io.ktor.http.auth.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.sessions.*
import org.mitre.web.OpenIdSessionStorage

class BasicOrSessionAuth internal constructor(config: Config): AuthenticationProvider(config) {

    val realm = config.realm

    private val authenticationFunction: AuthenticationFunction<UserPasswordCredential> =
        config.authenticationFunction

    override suspend fun onAuthenticate(context: AuthenticationContext) {
        val call = context.call
        val p = call.sessions.get<OpenIdSessionStorage>()?.principal
        if (p != null) {
            context.principal(name, p)
            return
        }

        val credentials = call.request.basicAuthenticationCredentials(Charsets.UTF_8)
        val principal = credentials?.let { authenticationFunction(call, it) }

        val cause = when {
            credentials == null -> AuthenticationFailedCause.NoCredentials
            principal == null -> AuthenticationFailedCause.InvalidCredentials
            else -> null
        }

        if (cause != null) {
            @Suppress("NAME_SHADOWING")
            context.challenge(basicOrSessionAuthChallengeKey, cause) { challenge, call ->
                call.respond(UnauthorizedResponse(HttpAuthHeader.basicAuthChallenge(realm, Charsets.UTF_8)))
                challenge.complete()
            }
        }
        if (principal != null) {
            context.principal(name, principal)
        }
    }

    class Config internal constructor(name: String?) : AuthenticationProvider.Config(name) {
        internal var authenticationFunction: AuthenticationFunction<UserPasswordCredential> = { null }
        public var realm: String = "Ktor Server"

        public fun validate(body: suspend ApplicationCall.(UserPasswordCredential) -> Any?) {
            authenticationFunction = body
        }

        internal fun build() = BasicOrSessionAuth(this)
    }

}

/**
 * Installs the form-based [Authentication] provider.
 * Form-based authentication uses a web form to collect credential information and authenticate a user.
 * To learn how to configure it, see [Form-based authentication](https://ktor.io/docs/form.html).
 */
fun AuthenticationConfig.basicOrSessionAuth(
    name: String? = null,
    configure: BasicOrSessionAuth.Config.() -> Unit
) {
    val provider = BasicOrSessionAuth.Config(name).apply(configure).build()
    register(provider)
}

/**
 * A context for [FormAuthChallengeFunction].
 */
class BasicOrSessionAuthChallengeContext(val call: ApplicationCall)

/**
 * Specifies what to send back if form-based authentication fails.
 */
typealias BasicOrSessionAuthChallengeFunction = suspend BasicOrSessionAuthChallengeContext.(UserPasswordCredential?) -> Unit

private val basicOrSessionAuthChallengeKey: Any = "BasicOrSessionAuth"
