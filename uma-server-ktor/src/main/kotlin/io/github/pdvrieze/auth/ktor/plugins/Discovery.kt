package io.github.pdvrieze.auth.ktor.plugins

import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.util.*
import org.mitre.discovery.web.DiscoveryEndpoint

fun OpenIdContext.wellKnown(configure: WellKnown.()-> Unit = {}) {
    WellKnownImpl(this).configure()
}

interface WellKnown: OpenIdContextExt {
    override val openIdContext: OpenIdContext
    val endpoint: DiscoveryEndpoint

    @KtorDsl
    public fun routing(configuration: Route.() -> Unit) {
        val a = openIdContext.application
        val r: Routing = a.pluginOrNull(Routing) ?: a.install(Routing)

        r.route("/.well-known") {
            configuration()
        }
    }

}

class WellKnownImpl(
    override val openIdContext: OpenIdContext
): WellKnown {

    override val endpoint: DiscoveryEndpoint by lazy {
        DiscoveryEndpoint(
            openIdContext.config,
            openIdContext.scopeService,
            openIdContext.signService,
            openIdContext.encryptionService,
            openIdContext.userService,
        )
    }

}
