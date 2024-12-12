package org.mitre.web.util

import io.github.pdvrieze.auth.Authentication
import io.github.pdvrieze.auth.ClientAuthentication
import io.github.pdvrieze.auth.ClientJwtAuthentication
import io.github.pdvrieze.auth.UserAuthentication
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mitre.oauth2.exception.AuthenticationException
import org.mitre.oauth2.model.GrantedAuthority

private suspend fun RoutingContext.getAuthOrRespondUnauthorized(): Authentication {
    return resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        throw AuthenticationException("Should be unreachable")
    }
}

suspend fun RoutingContext.requireRole(requiredRole: GrantedAuthority): Authentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (requiredRole !is UserAuthentication) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireUserRole(requiredRole: GrantedAuthority): UserAuthentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (authentication !is UserAuthentication || requiredRole !in authentication.authorities) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireUserRole(): UserAuthentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (authentication !is UserAuthentication) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireUserScope(a: GrantedAuthority, vararg scopes: String, action: () -> Nothing): UserAuthentication {
    return requireUserScope(*scopes)
}

suspend fun RoutingContext.requireUserScope(vararg scopes: String): UserAuthentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (authentication !is UserAuthentication || scopes.any { ! authentication.hasScope(it) }) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }


    return authentication
}

suspend fun RoutingContext.requireClientRole(): ClientAuthentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (authentication !is ClientAuthentication) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireClientTokenScope(vararg scopes: String): ClientJwtAuthentication {
    val authentication = getAuthOrRespondUnauthorized()
    if (authentication  !is ClientJwtAuthentication || scopes.any { ! authentication.hasScope(it) }) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireScope(
    scope: String,
): Authentication {

    val authentication = getAuthOrRespondUnauthorized()
    if (! authentication.hasScope(scope)) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

suspend fun RoutingContext.requireClientOrAdminRole(): Authentication {
    val authentication = resolveAuthenticatedUser() ?: run {
        call.respond(HttpStatusCode.Unauthorized)
        throw AuthenticationException("Should be unreachable")
    }
    if (authentication !is ClientAuthentication &&
        (authentication !is UserAuthentication || GrantedAuthority.ROLE_ADMIN !in authentication.authorities)) {
        call.respond(HttpStatusCode.Forbidden)
        throw AuthenticationException("Should be unreachable")
    }
    return authentication
}

