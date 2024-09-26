package org.mitre.web.util

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority
import org.mitre.oauth2.model.OAuth2AccessToken
import org.mitre.oauth2.model.OAuth2RequestAuthentication

inline suspend fun PipelineContext<Unit, ApplicationCall>.requireRole(requiredRole: GrantedAuthority, onMissing: (Authentication?) -> Nothing): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (requiredRole!in authentication.authorities) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}

inline suspend fun PipelineContext<Unit, ApplicationCall>.requireScope(
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
inline suspend fun PipelineContext<Unit, ApplicationCall>.requireRole(requiredRole: GrantedAuthority, vararg scopes: String, onMissing: (Authentication?) -> Nothing): OAuth2RequestAuthentication {
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

inline suspend fun PipelineContext<Unit, ApplicationCall>.requireRoleOf(requiredRole1: GrantedAuthority, requiredRole2: GrantedAuthority, onMissing: (Authentication?) -> Nothing): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        return onMissing(null)
    }
    if (requiredRole1 in authentication.authorities || requiredRole2 in authentication.authorities) {
        call.respond(HttpStatusCode.Forbidden)
        return onMissing(authentication)
    }
    return authentication
}

inline suspend fun PipelineContext<Unit, ApplicationCall>.requireRoleOf(requiredRoles: List<GrantedAuthority>, onMissing: (Authentication?) -> Nothing): Authentication {
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
