package io.github.pdvrieze.auth.ktor.plugins

import io.github.pdvrieze.openid.web.style.default.DefaultStyles
import io.ktor.server.application.*
import io.ktor.server.http.content.*
import io.ktor.server.resources.*
import io.ktor.server.routing.*
import org.mitre.discovery.web.DiscoveryEndpoint
import org.mitre.oauth2.web.DeviceEndpoint
import org.mitre.oauth2.web.IntrospectionEndpoint
import org.mitre.oauth2.web.OAuthConfirmationController
import org.mitre.oauth2.web.RevocationEndpoint
import org.mitre.oauth2.web.ScopeAPI
import org.mitre.oauth2.web.TokenAPI
import org.mitre.openid.connect.web.ApprovedSiteAPI
import org.mitre.openid.connect.web.BlacklistAPI
import org.mitre.openid.connect.web.ClientAPI
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint
import org.mitre.openid.connect.web.EndSessionEndpoint
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint
import org.mitre.openid.connect.web.RootController
import org.mitre.openid.connect.web.StatsAPI
import org.mitre.openid.connect.web.UserInfoEndpoint
import org.mitre.openid.connect.web.WhitelistAPI
import org.mitre.uma.web.AuthorizationRequestEndpoint
import org.mitre.uma.web.ClaimsCollectionEndpoint
import org.mitre.uma.web.PermissionRegistrationEndpoint
import org.mitre.uma.web.PolicyAPI
import org.mitre.uma.web.ResourceSetRegistrationEndpoint
import org.mitre.uma.web.UserClaimSearchHelper
import org.mitre.web.FormAuthEndpoint
import org.mitre.web.util.KtorEndpoint

fun Application.configureRouting(additional: Route.() -> Unit = {}) {
    install(Resources)
    routing {
        get("/resources/bootstrap2/css/bootstrap.css") { call.respondCss { with(DefaultStyles) { bootstrap() } } }
        get("/resources/bootstrap2/css/bootstrap-responsive.css") { call.respondCss { with(DefaultStyles) { bootstrapResponsive() } } }

        staticResources("/resources/bootstrap2", "bootstrap2")
        staticResources("/resources/css", "css")
        staticResources("/resources/images", "images")
        staticResources("/resources/images", "images")
        staticResources("/resources/js", "js")
        staticResources("/resources/template", "template")

        for (endpoint in endpoints) {
            with(endpoint) { addRoutes() }
        }

        additional()
    }
}

private val endpoints: List<KtorEndpoint> = listOf(
    RootController,
    FormAuthEndpoint,
    ScopeAPI,

    OAuthConfirmationController,
    DeviceEndpoint,
    RevocationEndpoint,
    TokenAPI,
    IntrospectionEndpoint,
//    UmaDiscoveryEndpoint,
    PolicyAPI,
    UserClaimSearchHelper,
    ResourceSetRegistrationEndpoint,
    PermissionRegistrationEndpoint,
    ClaimsCollectionEndpoint,
    JWKSetPublishingEndpoint,
    DiscoveryEndpoint,
    ApprovedSiteAPI,
    BlacklistAPI,
    ClientAPI,
//    DataAPI,
    DynamicClientRegistrationEndpoint,
    EndSessionEndpoint,
    ProtectedResourceRegistrationEndpoint,
    StatsAPI,
    UserInfoEndpoint,
    WhitelistAPI,
    AuthorizationRequestEndpoint,
)
