package org.mitre.web.util

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2RequestAuthentication

suspend inline fun RoutingContext.requireRole(requiredRole: GrantedAuthority, onMissing: (Authentication?) -> Nothing): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (requiredRole !in authentication.authorities) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}

suspend inline fun RoutingContext.requireScope(
    scope: String,
    onMissing: (Authentication?) -> Nothing,
): OAuth2RequestAuthentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (authentication !is OAuth2RequestAuthentication)  {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (scope !in authentication.oAuth2Request.scope) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}

/**
 * Variant that also requires scopes to be present
 */
suspend inline fun RoutingContext.requireRole(requiredRole: GrantedAuthority, vararg scopes: String, onMissing: (Authentication?) -> Nothing): OAuth2RequestAuthentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (authentication !is OAuth2RequestAuthentication) {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(authentication)
    }
    if (requiredRole!in authentication.authorities) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    if (scopes.any { it !in authentication.oAuth2Request.scope }) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }

    return authentication
}

suspend inline fun RoutingContext.requireRoleOf(requiredRole1: GrantedAuthority, requiredRole2: GrantedAuthority, onMissing: (Authentication?) -> Nothing): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (!(requiredRole1 in authentication.authorities || requiredRole2 in authentication.authorities)) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}

suspend inline fun RoutingContext.requireRoleOf(requiredRoles: List<GrantedAuthority>, onMissing: (Authentication?) -> Nothing): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (requiredRoles.none { it in authentication.authorities }) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}
