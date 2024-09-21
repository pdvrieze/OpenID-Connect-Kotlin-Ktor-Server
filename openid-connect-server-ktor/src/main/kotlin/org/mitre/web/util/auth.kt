package org.mitre.web.util

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.util.pipeline.*
import org.mitre.oauth2.model.Authentication
import org.mitre.oauth2.model.GrantedAuthority

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
